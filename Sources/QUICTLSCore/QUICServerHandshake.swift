/// Embedded-clean TLS 1.3 server handshake FSM (RFC 8446, RFC 9001), generic over
/// `C: CryptoProvider`.
///
/// The server-side analogue of ``QUICClientHandshake`` + ``QUICClientAuthMachine``:
/// a single value-type, sans-IO, caller-locked finite state machine spanning
/// ClientHello ingestion through the client Finished. It performs **no I/O**, holds
/// **no lock**, and never reaches for a clock — the QUICCrypto `ServerStateMachine`
/// adapter owns the `Mutex`, parses CRYPTO-frame bytes ↔ Foundation `Data`, runs
/// `TLSConfiguration`-dependent negotiation (cipher suite, groups, ALPN), X.509 /
/// raw-public-key trust evaluation, the swift-crypto ephemeral key generation +
/// (EC)DHE agreement, and the server CertificateVerify signing, and drives this core
/// under its lock.
///
/// ## Security invariants (preserved byte-for-byte)
///
/// - **PSK-binder validation** is `finishedVerifyData` over the truncated-ClientHello
///   transcript hash compared constant-time against the offered binder; a mismatch
///   means the PSK is not accepted (the adapter continues with a full handshake),
///   never a silent accept of an unauthenticated PSK.
/// - **Client CertificateVerify proof-of-possession is verified through
///   ``TLSSignatureVerifier``, fail-closed.** The CertificateVerify `algorithm` must
///   match the client key's intrinsic scheme; an invalid signature or a key-import
///   failure throws (`signatureVerificationFailed`), never proceeds.
/// - **Client Finished is verified** with a constant-time MAC before the resumption
///   secret is derived; a mismatch throws `finishedVerificationFailed`.
/// - **Transcript ordering** is owned solely by this core; HRR uses the RFC 8446
///   §4.4.1 `message_hash` synthetic transform so transcripts/secrets stay
///   byte-identical.
///
/// ## What stays adapter-side
///
/// - `TLSConfiguration`-dependent negotiation and *wire-extension assembly* (the
///   adapter hands the core the finished ServerHello / EncryptedExtensions /
///   CertificateRequest / Certificate messages).
/// - The swift-crypto ephemeral key generation + (EC)DHE shared-secret computation
///   (the core takes the already-computed shared secret).
/// - The server CertificateVerify *signing* (`any TLSSigningKey`, incl. HSM / custom
///   keys): the core hands out the transcript hash to sign over and the adapter folds
///   the signed CertificateVerify bytes back.
/// - X.509 parsing / chain / trust and the `certificateValidator` closure.
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, no `ContinuousClock`, no
/// swift-crypto, no X509/ASN.1, typed throws (closed ``QUICServerHandshakeError``),
/// no key paths.
import P2PCoreBytes
import P2PCoreCrypto

/// The TLS 1.3 server handshake FSM over the crypto seam.
public struct QUICServerHandshake<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// Position in the server flight.
    public enum ServerState: Sendable, Equatable {
        /// Before any ClientHello has been ingested.
        case start
        /// HelloRetryRequest sent; waiting for ClientHello2.
        case sentHelloRetryRequest
        /// ServerHello…Finished flight built; waiting for the client Certificate
        /// (mutual TLS).
        case waitClientCertificate
        /// Waiting for the client CertificateVerify (mutual TLS).
        case waitClientCertificateVerify
        /// Waiting for the client Finished.
        case waitFinished
        /// The handshake is complete.
        case connected
    }

    // MARK: - Stored Fields (all value types)

    /// The running transcript hash. **Owned by this core.**
    private var transcript: TLSTranscriptHashCore<C>

    /// The key schedule.
    private var keySchedule: TLSKeyScheduleCore<C>

    /// The negotiated cipher suite.
    private var cipherSuite: TLSCipherSuiteCore

    private var state: ServerState

    private var clientHandshakeSecret: [UInt8]?
    private var serverHandshakeSecret: [UInt8]?

    private var pskUsed: Bool

    // mTLS verification state: the client CertificateVerify algorithm must be one
    // the server offered in CertificateRequest.signature_algorithms.
    private var sentSignatureAlgorithms: [SignatureScheme]?
    private var requestedClientCertificate: Bool

    /// Captured secrets read back by the adapter post-handshake.
    public private(set) var clientApplicationSecret: [UInt8]?
    public private(set) var serverApplicationSecret: [UInt8]?
    public private(set) var exporterMasterSecret: [UInt8]?
    public private(set) var resumptionMasterSecret: [UInt8]?

    // MARK: - Initialization

    /// Constructs a fresh server FSM in the `start` state for the given provisional
    /// cipher suite (the suite is re-fixed when ClientHello negotiation resolves it).
    public init(cipherSuite: TLSCipherSuiteCore = .aes128GCMSHA256) {
        self.transcript = TLSTranscriptHashCore<C>(hash: cipherSuite.hash)
        self.keySchedule = TLSKeyScheduleCore<C>(cipherSuite: cipherSuite)
        self.cipherSuite = cipherSuite
        self.state = .start
        self.clientHandshakeSecret = nil
        self.serverHandshakeSecret = nil
        self.pskUsed = false
        self.sentSignatureAlgorithms = nil
        self.requestedClientCertificate = false
    }

    // MARK: - Accessors

    /// The current server state.
    public var currentState: ServerState { state }

    /// The negotiated (or provisional) cipher suite.
    public var negotiatedCipherSuite: TLSCipherSuiteCore { cipherSuite }

    /// Whether a PSK was accepted.
    public var pskWasUsed: Bool { pskUsed }

    /// The 0-RTT client early-traffic-secret, if it was derived during the flight.
    public private(set) var clientEarlyTrafficSecret: [UInt8]?

    /// The current key-schedule core (so the adapter can derive ticket PSKs
    /// post-handshake). The core is a value type.
    public var currentKeySchedule: TLSKeyScheduleCore<C> { keySchedule }

    // MARK: - PSK binder validation

    /// Validates a PSK binder against the truncated ClientHello.
    ///
    /// Derives the early secret from `psk`, the binder key from it, and compares the
    /// resulting `finishedVerifyData` over the truncated-ClientHello transcript hash
    /// against the offered binder in constant time. The transcript hash is computed
    /// with `cipherSuite`'s hash. Used during ClientHello processing (which is fully
    /// adapter-driven for negotiation); the binder check itself is security-critical
    /// and lives here so the seam HMAC path is exercised.
    ///
    /// - Returns: `true` iff the binder is valid (the adapter then accepts the PSK);
    ///   `false` otherwise (the adapter continues with a full handshake — never a
    ///   silent accept).
    public static func isValidPSKBinder(
        psk: [UInt8],
        cipherSuite: TLSCipherSuiteCore,
        truncatedClientHello: [UInt8],
        offeredBinder: [UInt8],
        isResumption: Bool
    ) throws(QUICServerHandshakeError) -> Bool {
        var schedule = TLSKeyScheduleCore<C>(cipherSuite: cipherSuite)
        schedule.deriveEarlySecret(psk: psk)

        let binderKey: [UInt8]
        do {
            binderKey = try schedule.deriveBinderKey(isResumption: isResumption)
        } catch {
            throw .keySchedule(error)
        }
        let finishedKey: [UInt8]
        do {
            finishedKey = try schedule.finishedKey(from: binderKey)
        } catch {
            throw .keySchedule(error)
        }

        var transcript = TLSTranscriptHashCore<C>(hash: cipherSuite.hash)
        transcript.update(with: truncatedClientHello)
        let expected = schedule.finishedVerifyData(
            forKey: finishedKey,
            transcriptHash: transcript.currentHash()
        )
        return constantTimeEqual(expected, offeredBinder)
    }

    // MARK: - HelloRetryRequest

    /// Applies the RFC 8446 §4.4.1 HelloRetryRequest transcript transform: folds
    /// ClientHello1 into the transcript, replaces it with the `message_hash`
    /// synthetic message of ClientHello1, and folds the HRR into it. Fixes the
    /// negotiated cipher suite. Only one HRR is permitted.
    ///
    /// - Parameters:
    ///   - cipherSuite: The negotiated cipher suite (carried into ClientHello2).
    ///   - clientHello1Bytes: The complete ClientHello1 handshake message.
    ///   - helloRetryRequestBytes: The complete HelloRetryRequest handshake message.
    public mutating func applyHelloRetryRequest(
        cipherSuite: TLSCipherSuiteCore,
        clientHello1Bytes: [UInt8],
        helloRetryRequestBytes: [UInt8]
    ) throws(QUICServerHandshakeError) {
        guard state == .start else {
            throw .unexpectedMessage(state.tag)
        }
        self.cipherSuite = cipherSuite

        transcript = TLSTranscriptHashCore<C>(hash: cipherSuite.hash)
        transcript.update(with: clientHello1Bytes)
        let ch1Hash = transcript.currentHash()
        transcript = TLSTranscriptHashCore<C>.fromMessageHash(
            clientHello1Hash: ch1Hash,
            hash: cipherSuite.hash
        )
        transcript.update(with: helloRetryRequestBytes)
        state = .sentHelloRetryRequest
    }

    // MARK: - ClientHello → server flight

    /// Accepted-PSK material: the resolved PSK bytes and the ticket's cipher suite
    /// (the early-secret hash). The adapter validates the binder (via
    /// ``isValidPSKBinder``) and resolves the session before passing this in; the
    /// core then installs the PSK early secret into the key schedule.
    public struct AcceptedPSK: Sendable {
        public let psk: [UInt8]
        public let cipherSuite: TLSCipherSuiteCore
        public init(psk: [UInt8], cipherSuite: TLSCipherSuiteCore) {
            self.psk = psk
            self.cipherSuite = cipherSuite
        }
    }

    /// The server's resolved per-handshake parameters for building the flight. The
    /// adapter computes all negotiation outcomes (which depend on `TLSConfiguration`)
    /// and hands them here; the core owns the transcript + key schedule + crypto.
    public struct FlightParameters: Sendable {
        /// The negotiated cipher suite.
        public let cipherSuite: TLSCipherSuiteCore
        /// The accepted PSK (skips Certificate/CertificateVerify), or `nil`.
        public let acceptedPSK: AcceptedPSK?
        /// The (EC)DHE shared secret the adapter already computed.
        public let sharedSecret: [UInt8]
        /// Whether 0-RTT early data was accepted (drives the 0-RTT-secret derivation).
        public let earlyDataAccepted: Bool
        /// Whether the server requested a client certificate (mutual TLS).
        public let requestClientCertificate: Bool
        /// The signature algorithms offered in CertificateRequest (validated against
        /// the client CertificateVerify later), or `nil` if no CR is sent.
        public let certificateRequestSignatureAlgorithms: [SignatureScheme]?

        public init(
            cipherSuite: TLSCipherSuiteCore,
            acceptedPSK: AcceptedPSK?,
            sharedSecret: [UInt8],
            earlyDataAccepted: Bool,
            requestClientCertificate: Bool,
            certificateRequestSignatureAlgorithms: [SignatureScheme]?
        ) {
            self.cipherSuite = cipherSuite
            self.acceptedPSK = acceptedPSK
            self.sharedSecret = sharedSecret
            self.earlyDataAccepted = earlyDataAccepted
            self.requestClientCertificate = requestClientCertificate
            self.certificateRequestSignatureAlgorithms = certificateRequestSignatureAlgorithms
        }
    }

    /// A request for the adapter to sign the server CertificateVerify over
    /// `transcriptHash` with its signing key and feed the signed bytes back via
    /// ``foldServerCertificateVerify(messageBytes:)``. Signing stays adapter-side so
    /// any signing-key conformer (incl. HSM / custom) is supported.
    public struct ServerCertificateVerifyRequest: Sendable, Equatable {
        public let transcriptHash: [UInt8]
        public init(transcriptHash: [UInt8]) {
            self.transcriptHash = transcriptHash
        }
    }

    /// Begins the server flight: ingests ClientHello, installs the early secret,
    /// folds ClientHello + ServerHello into the transcript, derives the handshake
    /// secrets, folds EncryptedExtensions + optional CertificateRequest + (non-PSK)
    /// the server Certificate, and — for a non-PSK handshake — returns a
    /// ``ServerCertificateVerifyRequest`` for the adapter to sign.
    ///
    /// The caller supplies the assembled wire messages. The core folds them in
    /// transcript order. For a non-PSK handshake the adapter then calls
    /// ``foldServerCertificateVerify`` and ``finishServerFlight``; PSK handshakes skip
    /// straight to ``finishServerFlight``.
    ///
    /// - Parameters:
    ///   - clientHelloBytes: The complete ClientHello handshake message (ClientHello2
    ///     after an HRR).
    ///   - parameters: The adapter-resolved negotiation outcomes.
    ///   - serverHelloBytes: The assembled ServerHello handshake message.
    ///   - encryptedExtensionsBytes: The assembled EncryptedExtensions message.
    ///   - certificateRequestBytes: The assembled CertificateRequest message (mTLS),
    ///     or `nil`.
    ///   - serverCertificateBytes: The assembled server Certificate message (non-PSK),
    ///     or `nil` for a PSK handshake.
    /// - Returns: the handshake-traffic secrets, the optional 0-RTT secret, and — for
    ///   a non-PSK handshake — the CertificateVerify signing request.
    public mutating func beginServerFlight(
        clientHelloBytes: [UInt8],
        parameters: FlightParameters,
        serverHelloBytes: [UInt8],
        encryptedExtensionsBytes: [UInt8],
        certificateRequestBytes: [UInt8]?,
        serverCertificateBytes: [UInt8]?
    ) throws(QUICServerHandshakeError) -> (
        handshakeSecrets: (client: [UInt8], server: [UInt8]),
        clientEarlyTrafficSecret: [UInt8]?,
        certificateVerifyRequest: ServerCertificateVerifyRequest?
    ) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .unexpectedMessage(state.tag)
        }

        self.cipherSuite = parameters.cipherSuite
        self.pskUsed = parameters.acceptedPSK != nil
        self.requestedClientCertificate = parameters.requestClientCertificate
        self.sentSignatureAlgorithms = parameters.certificateRequestSignatureAlgorithms

        // Install the early secret: from the PSK (at the ticket suite) for an accepted
        // PSK, else fresh at the negotiated suite.
        if let acceptedPSK = parameters.acceptedPSK {
            keySchedule = TLSKeyScheduleCore<C>(cipherSuite: acceptedPSK.cipherSuite)
            keySchedule.deriveEarlySecret(psk: acceptedPSK.psk)
        } else {
            keySchedule = TLSKeyScheduleCore<C>(cipherSuite: parameters.cipherSuite)
            keySchedule.deriveEarlySecret(psk: nil)
        }

        // Fold ClientHello. After a HelloRetryRequest the transcript already carries
        // message_hash(CH1) + HRR, and `clientHelloBytes` is ClientHello2.
        transcript.update(with: clientHelloBytes)

        // 0-RTT: the client_early_traffic_secret is derived over the *main* transcript
        // hash at the ClientHello-only point, matching the legacy server adapter.
        var earlyTrafficSecret: [UInt8]?
        if parameters.earlyDataAccepted, parameters.acceptedPSK != nil {
            do {
                earlyTrafficSecret = try keySchedule.deriveClientEarlyTrafficSecret(
                    transcriptHash: transcript.currentHash()
                )
            } catch {
                throw .keySchedule(error)
            }
        }
        clientEarlyTrafficSecret = earlyTrafficSecret

        // Fold ServerHello, then derive the handshake-traffic secrets over CH…SH.
        transcript.update(with: serverHelloBytes)
        let handshakeSecrets: (client: [UInt8], server: [UInt8])
        do {
            handshakeSecrets = try keySchedule.deriveHandshakeSecrets(
                sharedSecret: parameters.sharedSecret,
                transcriptHash: transcript.currentHash()
            )
        } catch {
            throw .keySchedule(error)
        }
        clientHandshakeSecret = handshakeSecrets.client
        serverHandshakeSecret = handshakeSecrets.server

        // EncryptedExtensions.
        transcript.update(with: encryptedExtensionsBytes)

        // CertificateRequest (mutual TLS).
        if let certificateRequestBytes {
            transcript.update(with: certificateRequestBytes)
        }

        // Non-PSK: fold the server Certificate and request a CertificateVerify
        // signature over the current transcript hash.
        var certificateVerifyRequest: ServerCertificateVerifyRequest?
        if parameters.acceptedPSK == nil {
            guard let serverCertificateBytes else {
                throw .internalInvariant(.nonPSKMissingServerCertificate)
            }
            transcript.update(with: serverCertificateBytes)
            certificateVerifyRequest = ServerCertificateVerifyRequest(
                transcriptHash: transcript.currentHash()
            )
        }

        return (handshakeSecrets, earlyTrafficSecret, certificateVerifyRequest)
    }

    /// Folds the adapter-signed server CertificateVerify into the transcript. Called
    /// only for a non-PSK handshake, after ``beginServerFlight`` returned a signing
    /// request.
    public mutating func foldServerCertificateVerify(
        messageBytes: [UInt8]
    ) throws(QUICServerHandshakeError) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .internalInvariant(.certificateVerifyFoldedOutOfOrder)
        }
        transcript.update(with: messageBytes)
    }

    /// Builds the server Finished, folds it into the transcript, derives the
    /// application + exporter secrets, and transitions to the wait-for-client phase.
    ///
    /// - Returns: the server Finished handshake-message bytes and the application +
    ///   exporter secrets. The adapter sends the Finished (and the earlier flight) and
    ///   installs the application keys.
    public mutating func finishServerFlight() throws(QUICServerHandshakeError) -> (
        serverFinished: [UInt8],
        applicationSecrets: (client: [UInt8], server: [UInt8]),
        exporterMasterSecret: [UInt8]
    ) {
        guard state == .start || state == .sentHelloRetryRequest else {
            throw .internalInvariant(.flightFinishedOutOfOrder)
        }
        guard let serverHandshakeSecret else {
            throw .internalInvariant(.missingHandshakeSecret)
        }

        // Server Finished.
        let serverFinishedKey: [UInt8]
        do {
            serverFinishedKey = try keySchedule.finishedKey(from: serverHandshakeSecret)
        } catch {
            throw .keySchedule(error)
        }
        let verifyData = keySchedule.finishedVerifyData(
            forKey: serverFinishedKey,
            transcriptHash: transcript.currentHash()
        )
        let serverFinishedMessage: [UInt8]
        do {
            serverFinishedMessage = try HandshakeMessageCodec.encode(
                type: .finished, content: verifyData)
        } catch {
            throw .wire(error)
        }
        transcript.update(with: serverFinishedMessage)

        // Application + exporter secrets over CH…server Finished.
        let appTranscriptHash = transcript.currentHash()
        let appSecrets: (client: [UInt8], server: [UInt8])
        do {
            appSecrets = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscriptHash)
        } catch {
            throw .keySchedule(error)
        }
        clientApplicationSecret = appSecrets.client
        serverApplicationSecret = appSecrets.server

        let exporter: [UInt8]
        do {
            exporter = try keySchedule.deriveExporterMasterSecret(transcriptHash: appTranscriptHash)
        } catch {
            throw .keySchedule(error)
        }
        exporterMasterSecret = exporter

        state = requestedClientCertificate ? .waitClientCertificate : .waitFinished
        return (serverFinishedMessage, appSecrets, exporter)
    }

    // MARK: - Client Certificate (mutual TLS)

    /// Ingests the client Certificate: records whether a certificate was presented
    /// and folds the message into the transcript. Parsing / trust stays adapter-side
    /// (the resolved peer key arrives at ``ingestClientCertificateVerify``).
    ///
    /// - Parameters:
    ///   - certificatePresented: Whether the client's Certificate carried an entry.
    ///   - rawMessageBytes: The complete client Certificate handshake message.
    /// - Returns: `true` if a CertificateVerify is expected next (a certificate was
    ///   presented); `false` if the client sent an empty Certificate (the next message
    ///   is the client Finished).
    public mutating func ingestClientCertificate(
        certificatePresented: Bool,
        rawMessageBytes: [UInt8]
    ) throws(QUICServerHandshakeError) -> Bool {
        guard state == .waitClientCertificate else {
            throw .unexpectedMessage(state.tag)
        }
        transcript.update(with: rawMessageBytes)
        if certificatePresented {
            state = .waitClientCertificateVerify
            return true
        } else {
            state = .waitFinished
            return false
        }
    }

    /// The client public key for CertificateVerify verification.
    ///
    /// The adapter resolves this from the client certificate; the FSM never touches
    /// X.509.
    public struct ClientPublicKey: Sendable {
        /// The raw key bytes (x963 for the NIST curves, raw for Ed25519).
        public let bytes: [UInt8]
        /// The signature scheme the key is for.
        public let scheme: SignatureScheme

        public init(bytes: [UInt8], scheme: SignatureScheme) {
            self.bytes = bytes
            self.scheme = scheme
        }
    }

    /// Ingests the client CertificateVerify and performs the **proof-of-possession
    /// signature check** through ``TLSSignatureVerifier``, fail-closed.
    ///
    /// The CertificateVerify `algorithm` must be one offered in the CertificateRequest
    /// and must match the client key's intrinsic scheme. An invalid signature, a
    /// scheme mismatch, or a missing key throws — never proceeds. The signature is
    /// verified over the transcript up to (not including) the CertificateVerify; the
    /// message is folded in afterward.
    ///
    /// - Parameters:
    ///   - algorithm: The CertificateVerify `algorithm` field.
    ///   - signature: The CertificateVerify `signature` field.
    ///   - clientPublicKey: The resolved client public key, or `nil` if the adapter
    ///     could not produce one.
    ///   - rawMessageBytes: The complete CertificateVerify handshake message.
    public mutating func ingestClientCertificateVerify(
        algorithm: SignatureScheme,
        signature: [UInt8],
        clientPublicKey: ClientPublicKey?,
        rawMessageBytes: [UInt8]
    ) throws(QUICServerHandshakeError) {
        guard state == .waitClientCertificateVerify else {
            throw .unexpectedMessage(state.tag)
        }

        // The algorithm MUST be one the server offered in its CertificateRequest.
        // RFC 8446 §4.3.2 makes signature_algorithms mandatory in a CertificateRequest,
        // and this point is reached only after one was sent (requestedClientCertificate
        // == true). A missing record is therefore a server misconfiguration — fail
        // closed rather than skipping the check ("absent ⇒ accept any" is a silent
        // relaxation of the offered-algorithms constraint).
        guard let sentAlgs = sentSignatureAlgorithms, sentAlgs.contains(algorithm) else {
            throw .signatureVerificationFailed
        }

        guard let key = clientPublicKey else {
            throw .missingClientVerificationKey
        }
        // The CertificateVerify algorithm must match the key's own scheme.
        guard key.scheme == algorithm else {
            throw .signatureVerificationFailed
        }

        // Transcript hash up to (not including) CertificateVerify.
        let transcriptHash = transcript.currentHash()
        let isValid: Bool
        do {
            isValid = try TLSSignatureVerifier<C>.verify(
                signature: signature.span,
                algorithm: algorithm,
                publicKeyBytes: key.bytes.span,
                transcriptHash: transcriptHash.span,
                isServer: false  // CLIENT CertificateVerify
            )
        } catch {
            throw .signature(error)
        }
        guard isValid else {
            throw .signatureVerificationFailed
        }

        transcript.update(with: rawMessageBytes)
        state = .waitFinished
    }

    // MARK: - Client Finished

    /// Ingests the client Finished, verifies its MAC (constant time, fail-closed),
    /// folds it into the transcript, and derives the resumption master secret.
    ///
    /// - Parameter verifyData: The client Finished `verify_data`.
    public mutating func ingestClientFinished(
        verifyData: [UInt8]
    ) throws(QUICServerHandshakeError) {
        guard state == .waitFinished else {
            throw .unexpectedMessage(state.tag)
        }
        guard let clientHandshakeSecret else {
            throw .internalInvariant(.missingHandshakeSecret)
        }

        let clientFinishedKey: [UInt8]
        do {
            clientFinishedKey = try keySchedule.finishedKey(from: clientHandshakeSecret)
        } catch {
            throw .keySchedule(error)
        }
        let expected = keySchedule.finishedVerifyData(
            forKey: clientFinishedKey,
            transcriptHash: transcript.currentHash()
        )
        guard constantTimeEqual(verifyData, expected) else {
            throw .finishedVerificationFailed
        }

        // Fold the client Finished, then derive the resumption secret.
        let clientFinishedMessage: [UInt8]
        do {
            clientFinishedMessage = try HandshakeMessageCodec.encode(
                type: .finished, content: verifyData)
        } catch {
            throw .wire(error)
        }
        transcript.update(with: clientFinishedMessage)
        do {
            resumptionMasterSecret = try keySchedule.deriveResumptionMasterSecret(
                transcriptHash: transcript.currentHash()
            )
        } catch {
            throw .keySchedule(error)
        }
        state = .connected
    }
}

// MARK: - State tag bridging

extension QUICServerHandshake.ServerState {
    /// The Embedded-clean tag for this state (for ``QUICServerHandshakeError``).
    var tag: QUICServerHandshakeStateTag {
        switch self {
        case .start: return .start
        case .sentHelloRetryRequest: return .sentHelloRetryRequest
        case .waitClientCertificate: return .waitClientCertificate
        case .waitClientCertificateVerify: return .waitClientCertificateVerify
        case .waitFinished: return .waitFinished
        case .connected: return .connected
        }
    }
}
