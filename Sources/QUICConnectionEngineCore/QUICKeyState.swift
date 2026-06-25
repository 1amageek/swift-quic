// QUICKeyState.swift
// The engine's packet-protection key state across the four encryption levels,
// including 1-RTT key-update support (RFC 9001 §6). Value type, generic over the
// crypto seam `C`; cipher-suite dispatch is the closed `SuiteProtector<C>` enum
// (no `any`). Embedded-clean: no Mutex, no Foundation.

import QUICWire
import QUICPacketProtectionCore
import P2PCoreCrypto

/// One direction's protector plus, for the application level, the live key-update
/// machinery (current/next read & write secrets and the current key phase).
struct QUICKeyState<C: CryptoProvider>: Sendable {
    /// Installed read (open) protectors per level.
    var readProtectors: [EncryptionLevel: SuiteProtector<C>] = [:]
    /// Installed write (seal) protectors per level.
    var writeProtectors: [EncryptionLevel: SuiteProtector<C>] = [:]

    // MARK: - Application key update (RFC 9001 §6)

    /// The current application read traffic secret (for deriving the next key).
    var appReadSecret: [UInt8]?
    /// The current application write traffic secret.
    var appWriteSecret: [UInt8]?
    /// The negotiated application cipher suite.
    var appSuite: QUICProtectionSuite?
    /// The current 1-RTT key phase bit we apply to outbound short-header packets.
    var currentKeyPhase: UInt8 = 0

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
            secrets = try QUICKeyDerivation<C>.initialSecrets(connectionID: connectionID, salt: salt)
        } catch {
            throw .packetProtection(error)
        }
        let readSecret = isClient ? secrets.server : secrets.client
        let writeSecret = isClient ? secrets.client : secrets.server
        let readProtector: SuiteProtector<C>
        let writeProtector: SuiteProtector<C>
        do {
            readProtector = try QUICKeyDerivation<C>.protector(secret: readSecret, suite: .aes128GCM)
            writeProtector = try QUICKeyDerivation<C>.protector(secret: writeSecret, suite: .aes128GCM)
        } catch {
            throw .packetProtection(error)
        }
        readProtectors[.initial] = readProtector
        writeProtectors[.initial] = writeProtector
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
            let p: SuiteProtector<C>
            do { p = try QUICKeyDerivation<C>.protector(secret: readSecret, suite: suite) }
            catch { throw .packetProtection(error) }
            readProtectors[level] = p
        }
        if let writeSecret {
            let p: SuiteProtector<C>
            do { p = try QUICKeyDerivation<C>.protector(secret: writeSecret, suite: suite) }
            catch { throw .packetProtection(error) }
            writeProtectors[level] = p
        }
        if level == .application {
            appReadSecret = readSecret
            appWriteSecret = writeSecret
            appSuite = suite
        }
    }

    /// Discards a level's keys (RFC 9001 §4.9). Idempotent.
    mutating func discard(level: EncryptionLevel) {
        readProtectors[level] = nil
        writeProtectors[level] = nil
    }

    /// Whether read keys for `level` are installed.
    func hasReadKeys(for level: EncryptionLevel) -> Bool {
        readProtectors[level] != nil
    }

    /// Whether write keys for `level` are installed.
    func hasWriteKeys(for level: EncryptionLevel) -> Bool {
        writeProtectors[level] != nil
    }

    /// The read protector for `level`, or a typed throw if absent (no silent drop).
    func readProtector(for level: EncryptionLevel) throws(QUICEngineError) -> SuiteProtector<C> {
        guard let p = readProtectors[level] else { throw .keysUnavailable(level) }
        return p
    }

    /// The write protector for `level`, or a typed throw if absent.
    func writeProtector(for level: EncryptionLevel) throws(QUICEngineError) -> SuiteProtector<C> {
        guard let p = writeProtectors[level] else { throw .keysUnavailable(level) }
        return p
    }

    /// Initiates a 1-RTT key update (RFC 9001 §6.1): derives the next generation
    /// of both read and write secrets, installs them, and flips the key phase.
    /// Returns the new key phase bit.
    mutating func initiateKeyUpdate() throws(QUICEngineError) -> UInt8 {
        guard let readSecret = appReadSecret,
              let writeSecret = appWriteSecret,
              let suite = appSuite else {
            throw .invalidState("key update requested before application keys installed")
        }
        let nextRead: [UInt8]
        let nextWrite: [UInt8]
        do {
            nextRead = try QUICKeyDerivation<C>.nextGenerationSecret(secret: readSecret)
            nextWrite = try QUICKeyDerivation<C>.nextGenerationSecret(secret: writeSecret)
        } catch { throw .packetProtection(error) }

        let newReadProtector: SuiteProtector<C>
        let newWriteProtector: SuiteProtector<C>
        do {
            newReadProtector = try QUICKeyDerivation<C>.protector(secret: nextRead, suite: suite)
            newWriteProtector = try QUICKeyDerivation<C>.protector(secret: nextWrite, suite: suite)
        } catch { throw .packetProtection(error) }

        appReadSecret = nextRead
        appWriteSecret = nextWrite
        readProtectors[.application] = newReadProtector
        writeProtectors[.application] = newWriteProtector
        currentKeyPhase ^= 1
        return currentKeyPhase
    }
}
