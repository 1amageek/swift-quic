/// Embedded-clean TLS 1.3 client pre-ServerHello FSM (RFC 8446, RFC 9001),
/// generic over `C: CryptoProvider`.
///
/// This is the first slice of the client handshake: ClientHello assembly
/// (including the PSK-binder computation and the 0-RTT early-traffic-secret
/// derivation), HelloRetryRequest processing (the RFC 8446 §4.4.1 `message_hash`
/// transcript transform), and ServerHello processing (handshake-secret derivation
/// over the exact ClientHello…ServerHello transcript). It is a value-type, sans-IO,
/// caller-locked finite state machine. It performs **no I/O**, holds **no lock**,
/// and never reaches for a clock — the QUICCrypto `ClientStateMachine` adapter owns
/// the `Mutex`, parses CRYPTO-frame bytes ↔ Foundation `Data`, runs
/// `TLSConfiguration`-dependent extension negotiation and ephemeral key generation /
/// (EC)DHE agreement, and drives this core under its lock.
///
/// ## Security invariants (preserved byte-for-byte)
///
/// - **Transcript ordering** is owned by this core from ClientHello onward; the
///   handshake secret is derived over the exact ClientHello…ServerHello transcript,
///   so secrets stay byte-identical.
/// - **PSK-binder correctness**: the binder is `finishedVerifyData` over the
///   truncated-ClientHello transcript hash, identical to the legacy two-pass build.
/// - **Downgrade-sentinel detection (RFC 8446 §4.1.3)** is available fail-closed via
///   ``hasDowngradeSentinel(_:)`` and the ``ingestServerHello`` `checkDowngrade`
///   flag. The legacy QUIC adapter does not perform a downgrade-sentinel check, so
///   the adapter drives this with `checkDowngrade: false` to stay byte-identical; the
///   helper is exposed for a future opt-in without re-deriving the constants.
///
/// ## What stays adapter-side
///
/// - `TLSConfiguration`-dependent extension selection (ALPN, SNI, supported groups,
///   signature algorithms, transport parameters) and ClientHello *extension assembly*
///   (the adapter hands the core the finished extension list, minus `pre_shared_key`).
/// - Ephemeral key generation and the (EC)DHE shared-secret computation (the legacy
///   adapter uses its swift-crypto `KeyExchange`; the core takes the already-computed
///   shared secret).
/// - Session-ticket validity (`Date`-dependent) and X.509 parsing/trust.
///
/// After ServerHello the core hands its owned transcript + key schedule to a
/// ``QUICClientAuthMachine`` via ``makeAuthMachine()`` so the post-ServerHello
/// authentication slice continues with a single transcript owner.
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, no `ContinuousClock`, no
/// swift-crypto, no X509/ASN.1, typed throws (closed ``QUICClientHandshakeError``),
/// no key paths.
import P2PCoreBytes
import P2PCoreCrypto

/// The TLS 1.3 client pre-ServerHello FSM over the crypto seam.
public struct QUICClientHandshake<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Position in the pre-ServerHello flight.
    public enum PreState: Sendable, Equatable {
        /// Before ClientHello has been produced.
        case start
        /// ClientHello sent; waiting for the first ServerHello.
        case waitServerHello
        /// HelloRetryRequest received; waiting for the second ServerHello.
        case waitServerHelloRetry
        /// ServerHello processed; the handshake secret is available and the core is
        /// ready to hand off to ``QUICClientAuthMachine``.
        case serverHelloProcessed
    }

    // MARK: - RFC 8446 §4.1.3 downgrade sentinels

    /// "DOWNGRD" + 0x01 — server negotiated TLS 1.2.
    public static var downgradeSentinelTLS12: [UInt8] {
        [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
    }
    /// "DOWNGRD" + 0x00 — server negotiated TLS 1.1 or below.
    public static var downgradeSentinelTLS11OrBelow: [UInt8] {
        [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]
    }

    /// Whether the given ServerHello random ends with a downgrade sentinel.
    public static func hasDowngradeSentinel(_ random: [UInt8]) -> Bool {
        guard random.count >= 8 else { return false }
        let tail = Array(random.suffix(8))
        return tail == downgradeSentinelTLS12 || tail == downgradeSentinelTLS11OrBelow
    }

    // MARK: - Stored Fields (all value types)

    /// The running transcript hash. **Owned by this core.**
    private var transcript: TLSTranscriptHashCore<C>

    /// The key schedule. For a PSK handshake it is advanced to the early-secret
    /// state during ``produceClientHello``; otherwise it is reinitialised at
    /// ServerHello with the negotiated cipher suite.
    private var keySchedule: TLSKeyScheduleCore<C>

    /// The negotiated cipher suite, resolved at ServerHello (carries the suite the
    /// auth FSM uses for the post-ServerHello flight). Before ServerHello it holds
    /// the main-transcript suite, updated to the HRR suite by HelloRetryRequest.
    private var cipherSuite: TLSCipherSuiteCore

    private var state: PreState

    /// Whether 0-RTT early data is being attempted (cleared on HelloRetryRequest).
    private var attemptingEarlyData: Bool

    /// Whether a HelloRetryRequest has already been processed (only one allowed).
    private var receivedHelloRetryRequest: Bool

    /// Captured outputs of ServerHello processing (read by the adapter).
    public private(set) var clientHandshakeSecret: [UInt8]?
    public private(set) var serverHandshakeSecret: [UInt8]?
    public private(set) var pskAccepted: Bool

    // MARK: - Initialization

    /// Constructs the pre-ServerHello machine for the given **main** transcript
    /// cipher suite.
    ///
    /// - Parameter cipherSuite: The cipher suite for the main transcript hash and the
    ///   (initial) key schedule. To stay byte-identical to the legacy adapter, the
    ///   PSK binder + 0-RTT early secret are computed with the PSK ticket's own suite
    ///   (see ``PSKBinderInput``), independent of this value.
    public init(cipherSuite: TLSCipherSuiteCore = .aes128GCMSHA256) {
        self.transcript = TLSTranscriptHashCore<C>(hash: cipherSuite.hash)
        self.keySchedule = TLSKeyScheduleCore<C>(cipherSuite: cipherSuite)
        self.cipherSuite = cipherSuite
        self.state = .start
        self.attemptingEarlyData = false
        self.receivedHelloRetryRequest = false
        self.clientHandshakeSecret = nil
        self.serverHandshakeSecret = nil
        self.pskAccepted = false
    }

    // MARK: - Accessors

    /// The current pre-ServerHello state.
    public var currentState: PreState { state }

    /// The negotiated (or provisional) cipher suite.
    public var negotiatedCipherSuite: TLSCipherSuiteCore { cipherSuite }

    /// Whether a HelloRetryRequest was processed.
    public var helloRetryRequestReceived: Bool { receivedHelloRetryRequest }

    /// The 0-RTT client early-traffic-secret, if it was derived for ClientHello1.
    public private(set) var clientEarlyTrafficSecret: [UInt8]?

    // MARK: - ClientHello: PSK binder + transcript

    /// PSK material for a resumption ClientHello.
    ///
    /// The binder (and the 0-RTT early-traffic-secret) use the **ticket's**
    /// cipher-suite hash (`binderCipherSuite`), which can differ from the main
    /// transcript suite — matching the legacy adapter byte-for-byte. The early secret
    /// must already have been installed into the key schedule by the adapter via
    /// ``installPSKEarlySecret(psk:binderCipherSuite:)`` before ``produceClientHello``.
    public struct PSKBinderInput: Sendable {
        public let isResumption: Bool
        /// The PSK ticket's cipher suite (selects the binder / early-secret hash).
        public let binderCipherSuite: TLSCipherSuiteCore
        public init(isResumption: Bool, binderCipherSuite: TLSCipherSuiteCore) {
            self.isResumption = isResumption
            self.binderCipherSuite = binderCipherSuite
        }
    }

    /// Installs the PSK early secret into the key schedule (resumption only). This
    /// re-bases the key schedule on the ticket's cipher suite and derives the early
    /// secret from `psk`, matching the legacy adapter, which does this in
    /// `startHandshake` before the two-pass binder build.
    public mutating func installPSKEarlySecret(
        psk: [UInt8],
        binderCipherSuite: TLSCipherSuiteCore
    ) {
        keySchedule = TLSKeyScheduleCore<C>(cipherSuite: binderCipherSuite)
        keySchedule.deriveEarlySecret(psk: psk)
    }

    /// Finalises a ClientHello whose `extensions` already contain everything EXCEPT
    /// the `pre_shared_key` extension (which must be last), computes the PSK binder
    /// when `pskBinder` is present, folds the resulting ClientHello into the
    /// transcript, and derives the 0-RTT early-traffic-secret when requested.
    ///
    /// For a non-PSK ClientHello (`pskBinder == nil` and `offeredPsks == nil`) the
    /// core encodes the ClientHello from `extensions`, folds it into the transcript,
    /// and returns its bytes.
    ///
    /// The binder computation matches the legacy two-pass build byte-for-byte: the
    /// early secret is derived from the PSK (installed via
    /// ``installPSKEarlySecret(psk:binderCipherSuite:)``), the binder key from the
    /// early secret, and the binder is `finishedVerifyData` over the
    /// truncated-ClientHello transcript hash. The truncation length is
    /// `OfferedPsks.bindersSize`.
    ///
    /// - Parameters:
    ///   - random: The 32-byte client random.
    ///   - legacySessionID: The legacy session id.
    ///   - cipherSuites: The offered cipher suites (in order).
    ///   - extensions: All extensions EXCEPT `pre_shared_key`.
    ///   - offeredPsks: The PSK offer (identities + placeholder binders), or `nil`.
    ///   - pskBinder: The PSK binder parameters, or `nil` for a non-PSK ClientHello.
    ///   - attemptEarlyData: Whether to derive the 0-RTT early-traffic-secret.
    /// - Returns: The complete ClientHello handshake-message bytes (header included)
    ///   and, when 0-RTT was requested, the derived `client_early_traffic_secret`.
    public mutating func produceClientHello(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?,
        attemptEarlyData: Bool
    ) throws(QUICClientHandshakeError) -> (clientHello: [UInt8], earlyTrafficSecret: [UInt8]?) {
        guard state == .start else {
            throw .unexpectedMessage(.start)
        }

        let clientHelloMessage = try buildClientHelloBytes(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions,
            offeredPsks: offeredPsks,
            pskBinder: pskBinder,
            binderTranscriptPrefix: nil
        )

        // Fold the ClientHello into the transcript.
        transcript.update(with: clientHelloMessage)

        // Derive the 0-RTT early-traffic-secret over the ClientHello transcript,
        // hashed with the ticket suite (the early-secret hash).
        var earlyTrafficSecret: [UInt8]?
        if attemptEarlyData, let pskBinder {
            attemptingEarlyData = true
            var earlyTranscript = TLSTranscriptHashCore<C>(hash: pskBinder.binderCipherSuite.hash)
            earlyTranscript.update(with: clientHelloMessage)
            do {
                earlyTrafficSecret = try keySchedule.deriveClientEarlyTrafficSecret(
                    transcriptHash: earlyTranscript.currentHash()
                )
            } catch {
                throw .keySchedule(error)
            }
        }

        clientEarlyTrafficSecret = earlyTrafficSecret
        state = .waitServerHello
        return (clientHelloMessage, earlyTrafficSecret)
    }

    /// Builds the ClientHello bytes, computing the PSK binder when `pskBinder` is
    /// present. `binderTranscriptPrefix` is the transcript over which the binder is
    /// computed BEFORE the truncated ClientHello is folded in: `nil` for the first
    /// ClientHello (fresh transcript at the ticket suite), or the running
    /// `message_hash`+HRR transcript for ClientHello2.
    private func buildClientHelloBytes(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?,
        binderTranscriptPrefix: TLSTranscriptHashCore<C>?
    ) throws(QUICClientHandshakeError) -> [UInt8] {
        guard let offeredPsks, let pskBinder else {
            return try encodeClientHello(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: cipherSuites,
                extensions: extensions
            )
        }

        // First pass: ClientHello with placeholder binders.
        var psk = offeredPsks
        var extensionsWithPsk = extensions
        extensionsWithPsk.append(.preSharedKeyClient(psk))
        let placeholder = try encodeClientHello(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensionsWithPsk
        )

        // Compute the truncated transcript (excluding the binders section).
        let bindersSectionSize = psk.bindersSize
        guard placeholder.count >= bindersSectionSize else {
            throw .internalInvariant(.clientHelloShorterThanBinders)
        }
        let truncated = Array(placeholder.prefix(placeholder.count - bindersSectionSize))

        // CH1: fresh binder transcript at the ticket suite. CH2 (after HRR): the
        // running main transcript (message_hash + HRR) copied — matching the legacy
        // adapter, which mixes the main-transcript hash with the ticket-suite key.
        var binderTranscript = binderTranscriptPrefix
            ?? TLSTranscriptHashCore<C>(hash: pskBinder.binderCipherSuite.hash)
        binderTranscript.update(with: truncated)
        let binderHash = binderTranscript.currentHash()

        let binderKey: [UInt8]
        do {
            binderKey = try keySchedule.deriveBinderKey(isResumption: pskBinder.isResumption)
        } catch {
            throw .keySchedule(error)
        }
        let finishedKeyForBinder: [UInt8]
        do {
            finishedKeyForBinder = try keySchedule.finishedKey(from: binderKey)
        } catch {
            throw .keySchedule(error)
        }
        let binder = keySchedule.finishedVerifyData(
            forKey: finishedKeyForBinder,
            transcriptHash: binderHash
        )

        // Second pass: ClientHello with the real binder.
        psk.binders = [binder]
        var finalExtensions = extensions
        finalExtensions.append(.preSharedKeyClient(psk))
        return try encodeClientHello(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: finalExtensions
        )
    }

    private func encodeClientHello(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension]
    ) throws(QUICClientHandshakeError) -> [UInt8] {
        do {
            let clientHello = try ClientHello(
                random: random,
                legacySessionID: legacySessionID,
                cipherSuites: cipherSuites,
                extensions: extensions
            )
            return try clientHello.encodeAsHandshakeBytes()
        } catch {
            throw .wire(error)
        }
    }

    // MARK: - HelloRetryRequest: synthetic transcript + ClientHello2

    /// Applies the RFC 8446 §4.4.1 HelloRetryRequest transcript transform: replaces
    /// the running transcript with the `message_hash` synthetic message of
    /// ClientHello1 and folds the HRR into it. The cipher suite is fixed to the HRR's
    /// suite (the second ServerHello must match it). 0-RTT is abandoned on HRR (RFC
    /// 8446 §4.2.10). Only one HRR is permitted.
    ///
    /// - Parameters:
    ///   - cipherSuite: The HelloRetryRequest cipher suite.
    ///   - rawMessageBytes: The complete HelloRetryRequest handshake message.
    public mutating func applyHelloRetryRequest(
        cipherSuite: TLSCipherSuiteCore,
        rawMessageBytes: [UInt8]
    ) throws(QUICClientHandshakeError) {
        guard state == .waitServerHello else {
            throw .unexpectedMessage(state.tag)
        }
        guard !receivedHelloRetryRequest else {
            throw .unexpectedMessage(state.tag)
        }
        receivedHelloRetryRequest = true
        attemptingEarlyData = false

        self.cipherSuite = cipherSuite

        // Synthetic message_hash(ClientHello1), then HRR.
        let clientHello1Hash = transcript.currentHash()
        transcript = TLSTranscriptHashCore<C>.fromMessageHash(
            clientHello1Hash: clientHello1Hash,
            hash: cipherSuite.hash
        )
        transcript.update(with: rawMessageBytes)
        state = .waitServerHelloRetry
    }

    /// Finalises a ClientHello2 after a HelloRetryRequest: optionally recomputes the
    /// PSK binder over the *current* transcript (which already contains the
    /// `message_hash` + HRR), folds ClientHello2 into the transcript, and returns its
    /// bytes. The 0-RTT early-traffic-secret is never derived for ClientHello2.
    ///
    /// - Parameters: as ``produceClientHello`` (minus `attemptEarlyData`).
    /// - Returns: The complete ClientHello2 handshake-message bytes.
    public mutating func produceClientHello2(
        random: [UInt8],
        legacySessionID: [UInt8],
        cipherSuites: [CipherSuite],
        extensions: [TLSExtension],
        offeredPsks: OfferedPsks?,
        pskBinder: PSKBinderInput?
    ) throws(QUICClientHandshakeError) -> [UInt8] {
        guard state == .waitServerHelloRetry else {
            throw .unexpectedMessage(state.tag)
        }

        // The ClientHello2 binder is computed over the running transcript
        // (message_hash + HRR) plus the truncated ClientHello2.
        let clientHelloMessage = try buildClientHelloBytes(
            random: random,
            legacySessionID: legacySessionID,
            cipherSuites: cipherSuites,
            extensions: extensions,
            offeredPsks: offeredPsks,
            pskBinder: pskBinder,
            binderTranscriptPrefix: transcript
        )

        transcript.update(with: clientHelloMessage)
        return clientHelloMessage
    }

    // MARK: - ServerHello

    /// Ingests a (non-HRR) ServerHello: optionally validates the downgrade sentinel
    /// (fail-closed), folds the ServerHello into the transcript, reinitialises the
    /// key schedule for the negotiated suite when no PSK was accepted, and derives the
    /// handshake-traffic secrets from the (already-computed) (EC)DHE shared secret.
    ///
    /// `TLSConfiguration`-dependent validation (cipher-suite-was-offered,
    /// session-id-echo, PSK selection rules) and the (EC)DHE agreement stay
    /// adapter-side; this method takes the already-resolved `pskAccepted` flag, the
    /// negotiated `cipherSuite`, the precomputed `sharedSecret`, the `serverRandom`
    /// (for the optional downgrade check), and the raw ServerHello bytes.
    ///
    /// - Parameters:
    ///   - serverRandom: The ServerHello.random (checked when `checkDowngrade`).
    ///   - cipherSuite: The negotiated cipher suite.
    ///   - pskAccepted: Whether the server accepted the offered PSK.
    ///   - sharedSecret: The (EC)DHE shared secret the adapter already computed.
    ///   - checkDowngrade: Whether to enforce the RFC 8446 §4.1.3 sentinel check. The
    ///     legacy QUIC adapter passes `false` (it performs no downgrade check), so
    ///     behaviour stays byte-identical.
    ///   - rawMessageBytes: The complete ServerHello handshake message.
    /// - Returns: the derived `{client,server}_handshake_traffic_secret`.
    public mutating func ingestServerHello(
        serverRandom: [UInt8],
        cipherSuite: TLSCipherSuiteCore,
        pskAccepted: Bool,
        sharedSecret: [UInt8],
        checkDowngrade: Bool,
        rawMessageBytes: [UInt8]
    ) throws(QUICClientHandshakeError) -> (client: [UInt8], server: [UInt8]) {
        guard state == .waitServerHello || state == .waitServerHelloRetry else {
            throw .unexpectedMessage(state.tag)
        }

        // RFC 8446 §4.1.3: downgrade protection — fail closed when enabled.
        if checkDowngrade, Self.hasDowngradeSentinel(serverRandom) {
            throw .downgradeDetected
        }

        self.cipherSuite = cipherSuite
        self.pskAccepted = pskAccepted

        // Fold ServerHello into the transcript.
        transcript.update(with: rawMessageBytes)

        // Reinitialise the key schedule for the negotiated suite when no PSK was
        // accepted (a PSK handshake already derived the early secret with the PSK).
        if !pskAccepted {
            keySchedule = TLSKeyScheduleCore<C>(cipherSuite: cipherSuite)
            keySchedule.deriveEarlySecret(psk: nil)
        }

        // Derive the handshake-traffic secrets over CH…SH.
        let transcriptHash = transcript.currentHash()
        let secrets: (client: [UInt8], server: [UInt8])
        do {
            secrets = try keySchedule.deriveHandshakeSecrets(
                sharedSecret: sharedSecret,
                transcriptHash: transcriptHash
            )
        } catch {
            throw .keySchedule(error)
        }

        clientHandshakeSecret = secrets.client
        serverHandshakeSecret = secrets.server
        state = .serverHelloProcessed
        return secrets
    }

    // MARK: - Hand-off to the authentication FSM

    /// Hands the owned transcript (CH…SH absorbed) and key schedule (at the
    /// handshake-secret state) to a ``QUICClientAuthMachine`` so the post-ServerHello
    /// authentication slice continues with a single transcript owner.
    ///
    /// - Returns: the authentication FSM, ready at the EncryptedExtensions boundary.
    public consuming func makeAuthMachine() throws(QUICClientHandshakeError) -> QUICClientAuthMachine<C> {
        guard state == .serverHelloProcessed,
              let clientHandshakeSecret,
              let serverHandshakeSecret else {
            throw .internalInvariant(.authMachineRequestedTooEarly)
        }
        return QUICClientAuthMachine<C>(
            transcript: transcript,
            keySchedule: keySchedule,
            cipherSuite: cipherSuite,
            clientHandshakeSecret: clientHandshakeSecret,
            serverHandshakeSecret: serverHandshakeSecret,
            pskUsed: pskAccepted
        )
    }

    /// The current transcript core (so the adapter can keep its own bridge in sync,
    /// e.g. before the auth FSM owns the transcript). The core is a value type.
    public var currentTranscript: TLSTranscriptHashCore<C> { transcript }

    /// The current key-schedule core (so the adapter can keep its bridge in sync).
    public var currentKeySchedule: TLSKeyScheduleCore<C> { keySchedule }
}

// MARK: - State tag bridging

extension QUICClientHandshake.PreState {
    /// The Embedded-clean tag for this state (for ``QUICClientHandshakeError``).
    var tag: QUICClientHandshakeStateTag {
        switch self {
        case .start: return .start
        case .waitServerHello: return .waitServerHello
        case .waitServerHelloRetry: return .waitServerHelloRetry
        case .serverHelloProcessed: return .serverHelloProcessed
        }
    }
}
