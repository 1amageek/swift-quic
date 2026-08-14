// QUICKeyState.swift
// The engine's packet-protection key state across the four encryption levels,
// including 1-RTT key-update support (RFC 9001 §6). Value type, generic over the
// crypto seam `C`; cipher-suite dispatch is the closed `SuiteProtector` enum
// (no `any`). Embedded-clean: no Mutex, no Foundation.

import QUICWire
import QUICPacketProtectionCore

private enum QUICProtectorSlot: Sendable {
    case empty
    case protector(SuiteProtector)
}

private struct QUICProtectorSlots: Sendable {
    var initial: QUICProtectorSlot = .empty
    var zeroRTT: QUICProtectorSlot = .empty
    var handshake: QUICProtectorSlot = .empty
    var application: QUICProtectorSlot = .empty

    subscript(level: EncryptionLevel) -> QUICProtectorSlot {
        get {
            switch level {
            case .initial: initial
            case .zeroRTT: zeroRTT
            case .handshake: handshake
            case .application: application
            }
        }
        set {
            switch level {
            case .initial: initial = newValue
            case .zeroRTT: zeroRTT = newValue
            case .handshake: handshake = newValue
            case .application: application = newValue
            }
        }
    }

    mutating func install(_ protector: SuiteProtector, for level: EncryptionLevel) {
        self[level] = .protector(protector)
    }

    mutating func discard(_ level: EncryptionLevel) {
        self[level] = .empty
    }
}

/// Directional packet-protection state, including the current, next, and previous
/// receive generations required by RFC 9001 key updates.
struct QUICKeyState: Sendable {
    /// Installed read (open) protectors per level.
    private var readProtectors = QUICProtectorSlots()
    /// Installed write (seal) protectors per level.
    private var writeProtectors = QUICProtectorSlots()
    /// Seal attempts are counted conservatively per key generation. Counting an
    /// attempt that fails before AEAD is safe; undercounting a completed seal is
    /// not. Counts reset exactly when a new write key is installed.
    private var writePacketCounts = EncryptionLevelSlots<UInt64>()
    /// Authentication failures are connection-wide across every key generation.
    private(set) var failedAuthenticationCount: UInt64 = 0

    // MARK: - Application key update (RFC 9001 §6)

    /// The current application read traffic secret (for deriving the next key).
    var appReadSecret: [UInt8]?
    /// The current application write traffic secret.
    var appWriteSecret: [UInt8]?
    /// The negotiated application cipher suite.
    var appSuite: QUICProtectionSuite?
    /// Stable application header-protection keys. RFC 9001 section 5.4 requires
    /// these keys to remain unchanged for the lifetime of the connection.
    private var appReadHeaderProtector: SuiteProtector?
    private var appWriteHeaderProtector: SuiteProtector?

    /// Receive generations are prepared before use and committed only after AEAD
    /// authentication succeeds. A previous generation is retained for reordered
    /// packets; packet numbers distinguish it from the subsequent same phase bit.
    private var nextAppReadSecret: [UInt8]?
    private var nextAppReadProtector: SuiteProtector?
    private var previousAppReadProtector: SuiteProtector?
    private var previousAppReadPhase: UInt8?
    private var currentReadPhaseFirstPacketNumber: UInt64?

    var hasPreviousReadGeneration: Bool {
        previousAppReadProtector != nil
    }

    /// Read and write phase bits advance independently until the responding peer
    /// switches its write keys, as required by RFC 9001 sections 6.1 and 6.2.
    private(set) var currentReadKeyPhase: UInt8 = 0
    private(set) var currentWriteKeyPhase: UInt8 = 0

    /// A subsequent locally initiated update is permitted only after a packet in
    /// the current write generation has been acknowledged.
    private var hasAdvancedWriteKeys = false
    private var currentWritePhaseFirstPacketNumber: UInt64?
    private var currentWritePhaseAcknowledged = true

    init() {}

    /// Installs an Initial-keys pair derived from the connection ID (RFC 9001
    /// §5.2). Initial keys are always AES-128-GCM.
    mutating func installInitial(
        connectionID: [UInt8],
        salt: [UInt8],
        isClient: Bool
    ) throws(QUICEngineError) {
        let secrets: (client: [UInt8], server: [UInt8])
        do {
            secrets = try QUICKeyDerivation.initialSecrets(connectionID: connectionID, salt: salt)
        } catch {
            throw .packetProtection(error)
        }
        let readSecret = isClient ? secrets.server : secrets.client
        let writeSecret = isClient ? secrets.client : secrets.server
        let readProtector: SuiteProtector
        let writeProtector: SuiteProtector
        do {
            readProtector = try QUICKeyDerivation.protector(secret: readSecret, suite: .aes128GCM)
            writeProtector = try QUICKeyDerivation.protector(secret: writeSecret, suite: .aes128GCM)
        } catch {
            throw .packetProtection(error)
        }
        readProtectors.install(readProtector, for: .initial)
        writeProtectors.install(writeProtector, for: .initial)
        writePacketCounts[.initial] = 0
    }

    /// Installs a handshake- or application-level keys pair from already-derived
    /// traffic secrets and a negotiated suite. For the application level it also
    /// records the secrets/suite needed for a later key update.
    mutating func install(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite,
        isClient: Bool
    ) throws(QUICEngineError) {
        if let readSecret {
            let p: SuiteProtector
            do { p = try QUICKeyDerivation.protector(secret: readSecret, suite: suite) }
            catch { throw .packetProtection(error) }
            readProtectors.install(p, for: level)
            if level == .application, appReadHeaderProtector == nil {
                appReadHeaderProtector = p
            }
        }
        if let writeSecret {
            let p: SuiteProtector
            do { p = try QUICKeyDerivation.protector(secret: writeSecret, suite: suite) }
            catch { throw .packetProtection(error) }
            writeProtectors.install(p, for: level)
            writePacketCounts[level] = 0
            if level == .application, appWriteHeaderProtector == nil {
                appWriteHeaderProtector = p
            }
        }
        if level == .application, readSecret != nil || writeSecret != nil {
            if let installedSuite = appSuite, installedSuite != suite {
                throw .invalidState("application traffic-secret directions use different cipher suites")
            }
            if let readSecret {
                appReadSecret = readSecret
            }
            if let writeSecret {
                appWriteSecret = writeSecret
            }
            appSuite = suite
            if readSecret != nil {
                try prepareNextReadGeneration()
            }
        }
    }

    /// Discards a level's keys (RFC 9001 §4.9). Idempotent.
    mutating func discard(level: EncryptionLevel) {
        readProtectors.discard(level)
        writeProtectors.discard(level)
    }

    /// Whether read keys for `level` are installed.
    func hasReadKeys(for level: EncryptionLevel) -> Bool {
        if case .protector = readProtectors[level] { return true }
        return false
    }

    /// Whether write keys for `level` are installed.
    func hasWriteKeys(for level: EncryptionLevel) -> Bool {
        if case .protector = writeProtectors[level] { return true }
        return false
    }

    /// The read protector for `level`, or a typed throw if absent (no silent drop).
    func readProtector(for level: EncryptionLevel) throws(QUICEngineError) -> SuiteProtector {
        switch readProtectors[level] {
        case .empty: throw .keysUnavailable(level)
        case .protector(let protector): return protector
        }
    }

    /// The write protector for `level`, or a typed throw if absent.
    func writeProtector(for level: EncryptionLevel) throws(QUICEngineError) -> SuiteProtector {
        switch writeProtectors[level] {
        case .empty: throw .keysUnavailable(level)
        case .protector(let protector): return protector
        }
    }

    func applicationReadHeaderProtectionProtector() throws(QUICEngineError) -> SuiteProtector {
        guard let protector = appReadHeaderProtector else {
            throw .keysUnavailable(.application)
        }
        return protector
    }

    func applicationWriteHeaderProtectionProtector() throws(QUICEngineError) -> SuiteProtector {
        guard let protector = appWriteHeaderProtector else {
            throw .keysUnavailable(.application)
        }
        return protector
    }

    func writePacketCount(for level: EncryptionLevel) -> UInt64 {
        writePacketCounts[level] ?? 0
    }

    mutating func recordSealAttempt(for level: EncryptionLevel) {
        let count = writePacketCounts[level] ?? 0
        writePacketCounts[level] = count == UInt64.max ? UInt64.max : count + 1
    }

    mutating func recordFailedAuthentication() -> UInt64 {
        if failedAuthenticationCount < UInt64.max {
            failedAuthenticationCount += 1
        }
        return failedAuthenticationCount
    }

    mutating func discardPreviousReadGeneration() {
        previousAppReadProtector = nil
        previousAppReadPhase = nil
    }

    /// Selects current, previous, or next receive keys without mutating state.
    /// The caller commits a next-generation selection only after AEAD succeeds.
    func applicationReadProtector(
        keyPhase: UInt8,
        packetNumber: UInt64
    ) -> SuiteProtector? {
        if keyPhase == currentReadKeyPhase {
            if case .protector(let protector) = readProtectors[.application] {
                return protector
            }
            return nil
        }

        if let previousAppReadPhase,
           previousAppReadPhase == keyPhase,
           let firstPacketNumber = currentReadPhaseFirstPacketNumber,
           packetNumber < firstPacketNumber {
            return previousAppReadProtector
        }

        return nextAppReadProtector
    }

    func packetUsesNextReadGeneration(keyPhase: UInt8, packetNumber: UInt64) -> Bool {
        guard keyPhase != currentReadKeyPhase else { return false }
        if let previousAppReadPhase,
           previousAppReadPhase == keyPhase,
           let firstPacketNumber = currentReadPhaseFirstPacketNumber,
           packetNumber < firstPacketNumber {
            return false
        }
        return true
    }

    /// Commits the prepared receive generation after successful authentication.
    mutating func commitNextReadGeneration(
        packetNumber: UInt64
    ) throws(QUICEngineError) -> UInt8 {
        guard let nextSecret = nextAppReadSecret,
              let nextProtector = nextAppReadProtector else {
            throw .invalidState("next application read keys are unavailable")
        }
        let currentProtector = try readProtector(for: .application)
        previousAppReadProtector = currentProtector
        previousAppReadPhase = currentReadKeyPhase
        currentReadPhaseFirstPacketNumber = packetNumber
        appReadSecret = nextSecret
        readProtectors.install(nextProtector, for: .application)
        currentReadKeyPhase ^= 1
        nextAppReadSecret = nil
        nextAppReadProtector = nil
        try prepareNextReadGeneration()
        return currentReadKeyPhase
    }

    /// Initiates a 1-RTT key update by advancing only the write generation and
    /// retaining current/next receive generations. The receive generation is
    /// committed later, after authenticating the peer's response.
    mutating func initiateKeyUpdate() throws(QUICEngineError) -> UInt8 {
        guard appReadSecret != nil, appWriteSecret != nil, appSuite != nil else {
            throw .invalidState("key update requested before application keys installed")
        }
        guard !hasAdvancedWriteKeys || currentWritePhaseAcknowledged else {
            throw .invalidState("a subsequent key update requires acknowledgment of the current write phase")
        }
        try prepareNextReadGeneration()
        return try advanceWriteGeneration()
    }

    /// Responds to an authenticated peer update before an ACK can be emitted.
    mutating func alignWriteGeneration(to keyPhase: UInt8) throws(QUICEngineError) {
        guard keyPhase != currentWriteKeyPhase else { return }
        _ = try advanceWriteGeneration()
        guard currentWriteKeyPhase == keyPhase else {
            throw .protocolViolation("peer key phase cannot be reached by one update")
        }
    }

    mutating func recordApplicationPacketSent(_ packetNumber: UInt64) {
        guard hasAdvancedWriteKeys, currentWritePhaseFirstPacketNumber == nil else { return }
        currentWritePhaseFirstPacketNumber = packetNumber
    }

    mutating func recordApplicationPacketAcknowledged(_ packetNumber: UInt64) {
        guard let firstPacketNumber = currentWritePhaseFirstPacketNumber,
              packetNumber >= firstPacketNumber else { return }
        currentWritePhaseAcknowledged = true
    }

    private mutating func prepareNextReadGeneration() throws(QUICEngineError) {
        guard nextAppReadProtector == nil else { return }
        guard let readSecret = appReadSecret, let suite = appSuite else { return }
        let nextSecret: [UInt8]
        let nextProtector: SuiteProtector
        do {
            nextSecret = try QUICKeyDerivation.nextGenerationSecret(secret: readSecret)
            nextProtector = try QUICKeyDerivation.protector(secret: nextSecret, suite: suite)
        } catch {
            throw .packetProtection(error)
        }
        nextAppReadSecret = nextSecret
        nextAppReadProtector = nextProtector
    }

    private mutating func advanceWriteGeneration() throws(QUICEngineError) -> UInt8 {
        guard let writeSecret = appWriteSecret, let suite = appSuite else {
            throw .invalidState("application write keys are unavailable")
        }
        let nextSecret: [UInt8]
        let nextProtector: SuiteProtector
        do {
            nextSecret = try QUICKeyDerivation.nextGenerationSecret(secret: writeSecret)
            nextProtector = try QUICKeyDerivation.protector(secret: nextSecret, suite: suite)
        } catch {
            throw .packetProtection(error)
        }
        appWriteSecret = nextSecret
        writeProtectors.install(nextProtector, for: .application)
        writePacketCounts[.application] = 0
        currentWriteKeyPhase ^= 1
        hasAdvancedWriteKeys = true
        currentWritePhaseFirstPacketNumber = nil
        currentWritePhaseAcknowledged = false
        return currentWriteKeyPhase
    }
}
