/// TLS 1.3 client post-ServerHello authentication FSM (RFC 8446 §4.4, RFC 9001),
/// Embedded-clean and generic over `C: CryptoProvider`.
///
/// This is the sans-IO, caller-locked, value-type core that drives the client side
/// of the handshake from EncryptedExtensions through the server Finished and the
/// client's own Finished (plus the optional mTLS Certificate/CertificateVerify
/// flight). It owns the running transcript hash and the key schedule by value; the
/// QUICCrypto adapter holds the FSM under its `Mutex`, parses CRYPTO-frame bytes
/// into the wire message types, performs X.509 parse/validate, and converts the
/// FSM's returned secrets into per-encryption-level `TLSOutput`s.
///
/// ## Security invariants (preserved byte-identically from the host FSM)
///
/// - **CertificateVerify is always verified whenever a certificate is presented**,
///   independent of `verifyPeer`. `verifyPeer` gates only X.509 chain/trust
///   validation (adapter-side); it never gates the handshake proof-of-possession
///   signature. Verification goes through ``TLSSignatureVerifier`` and fails closed
///   on any mismatch or missing key.
/// - **The server Finished MAC is verified** (constant-time) before the
///   application secrets are derived.
/// - **Strict message ordering**: a Finished is accepted only in `.waitFinished`. A
///   full (certificate) handshake reaches `.waitFinished` only after Certificate +
///   CertificateVerify; a PSK/resumption handshake transitions there directly after
///   EncryptedExtensions (Certificate legitimately omitted). Accepting a Finished
///   earlier would let a server skip authentication entirely (MITM) — forbidden.
///
/// X.509 cert parsing/validation and the `any`-bearing custom signing-key path stay
/// adapter-side: the core takes raw peer public-key bytes + a `certificatePresented`
/// flag, and for the client flight it takes the already-signed CertificateVerify
/// bytes (the adapter signs with its key).
///
/// Embedded-clean: no Foundation, no `any`, no Mutex, no `ContinuousClock`, no
/// swift-crypto, no X509, no key paths. Typed throws (closed ``TLSClientAuthError``).
import P2PCoreBytes
import P2PCoreCrypto

/// The client post-ServerHello authentication FSM over the crypto seam.
public struct QUICClientAuthMachine<C: CryptoProvider>: Sendable {

    // MARK: - State

    /// The states this FSM walks after ServerHello has been processed.
    public enum AuthState: Sendable, Equatable {
        case waitEncryptedExtensions
        case waitCertificateOrCertificateRequest
        case waitCertificate
        case waitCertificateVerify
        case waitFinished
        case connected
    }

    /// The current FSM state.
    public private(set) var state: AuthState

    // MARK: - Owned state (by value)

    /// The running transcript hash (CH..SH already folded by the adapter before the
    /// FSM was constructed; the FSM folds every subsequent message in order).
    private var transcript: TLSTranscriptHashCore<C>

    /// The key schedule, already at the handshake-secret stage.
    private var keySchedule: TLSKeyScheduleCore<C>

    /// The negotiated cipher suite (drives the hash and HKDF lengths).
    public let cipherSuite: TLSCipherSuiteCore

    /// The client/server handshake traffic secrets (derived from ServerHello).
    private let clientHandshakeSecret: [UInt8]
    private let serverHandshakeSecret: [UInt8]

    /// Whether a PSK was accepted (Certificate flight is skipped in PSK mode).
    private let pskUsed: Bool

    // MARK: - mTLS state

    /// Whether the server sent a CertificateRequest (client must respond with a
    /// Certificate, and a CertificateVerify when it has signing material).
    public private(set) var clientCertificateRequested: Bool

    /// Whether a (non-empty) server certificate was presented. Drives the
    /// fail-closed branch in CertificateVerify verification.
    private var serverCertificatePresented: Bool

    // MARK: - Derived output secrets (read by the adapter)

    /// The client/server application (1-RTT) traffic secrets.
    public private(set) var clientApplicationSecret: [UInt8]?
    public private(set) var serverApplicationSecret: [UInt8]?

    /// The exporter master secret (RFC 8446 §7.5).
    public private(set) var exporterMasterSecret: [UInt8]?

    /// The resumption master secret (for NewSessionTicket → PSK derivation).
    public private(set) var resumptionMasterSecret: [UInt8]?

    // MARK: - Initialization

    /// Constructs the auth FSM from the post-ServerHello state.
    ///
    /// - Parameters:
    ///   - transcript: The running transcript with CH..SH already folded.
    ///   - keySchedule: The key schedule at the handshake-secret stage.
    ///   - cipherSuite: The negotiated cipher suite.
    ///   - clientHandshakeSecret: `c hs traffic` (for the client Finished MAC).
    ///   - serverHandshakeSecret: `s hs traffic` (for the server Finished MAC).
    ///   - pskUsed: Whether a PSK was accepted (Certificate flight is skipped).
    public init(
        transcript: TLSTranscriptHashCore<C>,
        keySchedule: TLSKeyScheduleCore<C>,
        cipherSuite: TLSCipherSuiteCore,
        clientHandshakeSecret: [UInt8],
        serverHandshakeSecret: [UInt8],
        pskUsed: Bool
    ) {
        self.state = .waitEncryptedExtensions
        self.transcript = transcript
        self.keySchedule = keySchedule
        self.cipherSuite = cipherSuite
        self.clientHandshakeSecret = clientHandshakeSecret
        self.serverHandshakeSecret = serverHandshakeSecret
        self.pskUsed = pskUsed
        self.clientCertificateRequested = false
        self.serverCertificatePresented = false
    }

    // MARK: - Transcript handoff

    /// The current transcript core (so the adapter can read it back, e.g. for
    /// NewSessionTicket-related derivations) after the handshake completes.
    public var currentTranscript: TLSTranscriptHashCore<C> { transcript }

    /// The current key-schedule core (so the adapter can read it back, e.g. for
    /// post-handshake key updates and resumption).
    public var currentKeySchedule: TLSKeyScheduleCore<C> { keySchedule }

    /// The current transcript hash value (for adapter-side certificate validators
    /// that need the CH..CertificateVerify transcript, etc.).
    public var transcriptHash: [UInt8] { transcript.currentHash() }

    // MARK: - EncryptedExtensions

    /// Folds the EncryptedExtensions message into the transcript and transitions.
    ///
    /// The adapter has already validated ALPN and extracted the transport
    /// parameters from the parsed message; the FSM only enforces ordering, folds the
    /// raw bytes, and chooses the next state (PSK skips Certificate/CertificateVerify).
    ///
    /// - Parameter rawMessageBytes: The complete EncryptedExtensions handshake
    ///   message (4-byte header + content).
    public mutating func ingestEncryptedExtensions(
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitEncryptedExtensions else {
            throw .unexpectedMessage(state.tag)
        }
        transcript.update(with: rawMessageBytes)
        state = pskUsed ? .waitFinished : .waitCertificateOrCertificateRequest
    }

    // MARK: - CertificateRequest (mTLS)

    /// Folds a CertificateRequest into the transcript and records that the server
    /// requested client authentication (RFC 8446 §4.3.2).
    ///
    /// - Parameter rawMessageBytes: The complete CertificateRequest message.
    public mutating func ingestCertificateRequest(
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitCertificateOrCertificateRequest else {
            throw .unexpectedMessage(state.tag)
        }
        transcript.update(with: rawMessageBytes)
        clientCertificateRequested = true
        state = .waitCertificate
    }

    // MARK: - Server Certificate

    /// Folds the server Certificate into the transcript and transitions to
    /// `.waitCertificateVerify`.
    ///
    /// The adapter parses/validates the certificate chain (X.509) and extracts the
    /// peer public key; the FSM only records whether a certificate was presented
    /// (drives the fail-closed CertificateVerify branch) and folds the raw bytes.
    ///
    /// - Parameters:
    ///   - certificatePresented: Whether the Certificate message carried a non-empty
    ///     certificate list.
    ///   - rawMessageBytes: The complete Certificate handshake message.
    public mutating func ingestServerCertificate(
        certificatePresented: Bool,
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitCertificate || state == .waitCertificateOrCertificateRequest else {
            throw .unexpectedMessage(state.tag)
        }
        serverCertificatePresented = certificatePresented
        transcript.update(with: rawMessageBytes)
        state = .waitCertificateVerify
    }

    // MARK: - Server CertificateVerify

    /// The peer public key for CertificateVerify verification.
    ///
    /// The adapter resolves this from the certificate (or the configured
    /// `expectedPeerPublicKey`); the FSM never touches X.509.
    public struct PeerPublicKey: Sendable {
        /// The raw key bytes (x963 for the NIST curves, raw for Ed25519).
        public let bytes: [UInt8]
        /// The signature scheme the key is for.
        public let scheme: SignatureScheme

        public init(bytes: [UInt8], scheme: SignatureScheme) {
            self.bytes = bytes
            self.scheme = scheme
        }
    }

    /// Verifies the server CertificateVerify and folds it into the transcript.
    ///
    /// The proof-of-possession signature is verified **whenever a certificate was
    /// presented**, independent of `verifyPeer`. If a certificate was presented but
    /// no key is available, the handshake fails closed — never a silent accept.
    ///
    /// - Parameters:
    ///   - algorithm: The CertificateVerify `algorithm` field.
    ///   - signature: The CertificateVerify `signature` field.
    ///   - peerPublicKey: The peer key the adapter extracted, or `nil` if none is
    ///     available.
    ///   - verifyPeer: Whether peer authentication is required (gates the
    ///     no-key-available fail-closed branch alongside `certificatePresented`).
    ///   - rawMessageBytes: The complete CertificateVerify handshake message.
    public mutating func ingestServerCertificateVerify(
        algorithm: SignatureScheme,
        signature: [UInt8],
        peerPublicKey: PeerPublicKey?,
        verifyPeer: Bool,
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitCertificateVerify else {
            throw .unexpectedMessage(state.tag)
        }

        // The transcript hash up to (but not including) CertificateVerify.
        let transcriptHashValue = transcript.currentHash()

        if let key = peerPublicKey {
            // The CertificateVerify algorithm must match the key's own scheme.
            guard key.scheme == algorithm else {
                throw .signatureVerificationFailed
            }

            let isValid: Bool
            do {
                isValid = try TLSSignatureVerifier<C>.verify(
                    signature: signature.span,
                    algorithm: algorithm,
                    publicKeyBytes: key.bytes.span,
                    transcriptHash: transcriptHashValue.span,
                    isServer: true
                )
            } catch {
                throw .signature(error)
            }

            guard isValid else {
                throw .signatureVerificationFailed
            }
        } else if serverCertificatePresented || verifyPeer {
            // A certificate (or CertificateVerify) was presented but no key is
            // available to verify possession. Fail closed — proof of possession is
            // mandatory whenever the peer authenticates, independent of verifyPeer.
            throw .certificateVerificationFailed
        }

        transcript.update(with: rawMessageBytes)
        state = .waitFinished
    }

    // MARK: - Server Finished

    /// The secrets the adapter consumes after the server Finished is verified.
    public struct PostFinishedSecrets: Sendable {
        /// The client/server application (1-RTT) traffic secrets.
        public let clientApplicationSecret: [UInt8]
        public let serverApplicationSecret: [UInt8]
        /// The exporter master secret (RFC 8446 §7.5).
        public let exporterMasterSecret: [UInt8]
    }

    /// Verifies the server Finished MAC, folds it, and derives the application and
    /// exporter secrets.
    ///
    /// Finished is accepted only in `.waitFinished` (the ordering guard that blocks
    /// the auth-skip attack). The MAC is verified constant-time before any secret is
    /// derived.
    ///
    /// - Parameter verifyData: The server Finished `verify_data`.
    /// - Returns: The application + exporter secrets the adapter exposes as keys.
    public mutating func ingestServerFinished(
        verifyData: [UInt8]
    ) throws(TLSClientAuthError) -> PostFinishedSecrets {
        guard state == .waitFinished else {
            throw .unexpectedMessage(state.tag)
        }

        // Verify the server Finished MAC over the transcript up to (not including)
        // the Finished message.
        let serverFinishedKey: [UInt8]
        do {
            serverFinishedKey = try keySchedule.finishedKey(from: serverHandshakeSecret)
        } catch {
            throw .keySchedule(error)
        }
        let finishedTranscript = transcript.currentHash()
        let expected = keySchedule.finishedVerifyData(
            forKey: serverFinishedKey,
            transcriptHash: finishedTranscript
        )
        guard constantTimeEqual(verifyData, expected) else {
            throw .finishedVerificationFailed
        }

        // Fold the server Finished into the transcript.
        let serverFinishedMessage: [UInt8]
        do {
            serverFinishedMessage = try HandshakeMessageCodec.encode(
                type: .finished, content: verifyData)
        } catch {
            throw .wire(error)
        }
        transcript.update(with: serverFinishedMessage)

        // Derive application + exporter secrets over CH..server-Finished.
        let appTranscript = transcript.currentHash()
        let appSecrets: (client: [UInt8], server: [UInt8])
        do {
            appSecrets = try keySchedule.deriveApplicationSecrets(transcriptHash: appTranscript)
        } catch {
            throw .keySchedule(error)
        }
        let exporter: [UInt8]
        do {
            exporter = try keySchedule.deriveExporterMasterSecret(transcriptHash: appTranscript)
        } catch {
            throw .keySchedule(error)
        }

        clientApplicationSecret = appSecrets.client
        serverApplicationSecret = appSecrets.server
        exporterMasterSecret = exporter

        return PostFinishedSecrets(
            clientApplicationSecret: appSecrets.client,
            serverApplicationSecret: appSecrets.server,
            exporterMasterSecret: exporter
        )
    }

    // MARK: - Client flight (mTLS Certificate + CertificateVerify)

    /// Folds a client Certificate message into the transcript (mTLS).
    ///
    /// The adapter builds the Certificate message (echoing the
    /// certificate_request_context); the FSM folds it so the CertificateVerify and
    /// Finished are computed over the correct transcript.
    ///
    /// - Parameter rawMessageBytes: The complete client Certificate message.
    public mutating func foldClientCertificate(
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitFinished else {
            throw .unexpectedMessage(state.tag)
        }
        transcript.update(with: rawMessageBytes)
    }

    /// The transcript hash the adapter must sign for the client CertificateVerify
    /// (CH..client-Certificate). The adapter signs this with its `any`-bearing
    /// signing key (the seam signer ``TLSSignatureSigner`` could be used too, but
    /// the signing-key path is adapter-side).
    public var clientCertificateVerifyTranscript: [UInt8] { transcript.currentHash() }

    /// Folds a client CertificateVerify message into the transcript (mTLS).
    ///
    /// - Parameter rawMessageBytes: The complete client CertificateVerify message
    ///   (the adapter signed and encoded it).
    public mutating func foldClientCertificateVerify(
        rawMessageBytes: [UInt8]
    ) throws(TLSClientAuthError) {
        guard state == .waitFinished else {
            throw .unexpectedMessage(state.tag)
        }
        transcript.update(with: rawMessageBytes)
    }

    // MARK: - Client Finished

    /// Produces the client Finished message, folds it, derives the resumption master
    /// secret, and transitions to `.connected`.
    ///
    /// This must be called after the server Finished has been verified (and after the
    /// optional client Certificate/CertificateVerify flight has been folded for
    /// mTLS). It computes the client `verify_data` over the current transcript.
    ///
    /// - Returns: The complete client Finished handshake message bytes.
    public mutating func produceClientFinished() throws(TLSClientAuthError) -> [UInt8] {
        guard state == .waitFinished else {
            throw .unexpectedMessage(state.tag)
        }

        let clientFinishedKey: [UInt8]
        do {
            clientFinishedKey = try keySchedule.finishedKey(from: clientHandshakeSecret)
        } catch {
            throw .keySchedule(error)
        }
        let clientFinishedTranscript = transcript.currentHash()
        let clientVerifyData = keySchedule.finishedVerifyData(
            forKey: clientFinishedKey,
            transcriptHash: clientFinishedTranscript
        )

        let clientFinishedMessage: [UInt8]
        do {
            clientFinishedMessage = try HandshakeMessageCodec.encode(
                type: .finished, content: clientVerifyData)
        } catch {
            throw .wire(error)
        }

        // Fold the client Finished, then derive the resumption master secret over
        // CH..client-Finished.
        transcript.update(with: clientFinishedMessage)
        let resumptionTranscript = transcript.currentHash()
        let resumption: [UInt8]
        do {
            resumption = try keySchedule.deriveResumptionMasterSecret(
                transcriptHash: resumptionTranscript)
        } catch {
            throw .keySchedule(error)
        }
        resumptionMasterSecret = resumption

        state = .connected
        return clientFinishedMessage
    }
}

// MARK: - State tag bridging

extension QUICClientAuthMachine.AuthState {
    /// The Embedded-clean tag for this state (for ``TLSClientAuthError``).
    var tag: TLSAuthStateTag {
        switch self {
        case .waitEncryptedExtensions: return .waitEncryptedExtensions
        case .waitCertificateOrCertificateRequest: return .waitCertificateOrCertificateRequest
        case .waitCertificate: return .waitCertificate
        case .waitCertificateVerify: return .waitCertificateVerify
        case .waitFinished: return .waitFinished
        case .connected: return .connected
        }
    }
}
