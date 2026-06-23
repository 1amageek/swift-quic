/// Typed errors for the Embedded-clean TLS 1.3 client post-ServerHello auth FSM
/// (``QUICClientAuthMachine``).
///
/// These are handshake-correctness and authentication errors. Every failure is
/// surfaced explicitly to the caller (no silent fallback): an out-of-order message,
/// a CertificateVerify signature mismatch, or a Finished MAC mismatch fails the
/// handshake closed. The adapter maps each case to the corresponding TLS alert
/// before converting it into a QUIC CONNECTION_CLOSE frame.
///
/// Embedded-clean: no Foundation, no `any`. A closed enum; never silently swallowed.
import P2PCoreCrypto

/// Errors raised by the client post-ServerHello authentication FSM.
public enum TLSClientAuthError: Error, Sendable, Equatable {
    /// A handshake message arrived in a state where it is not permitted (e.g. a
    /// Finished before Certificate/CertificateVerify — the auth-skip attack).
    case unexpectedMessage(TLSAuthStateTag)

    /// The negotiated ALPN protocol is missing or was not one the client offered.
    case noALPNMatch

    /// A required handshake extension was absent (e.g. quic_transport_parameters).
    case missingExtension(TLSAuthExtensionTag)

    /// An extension was malformed or otherwise invalid for the negotiated context.
    case invalidExtension

    /// The CertificateVerify proof-of-possession signature did not validate, or the
    /// signature scheme did not match the peer key.
    case signatureVerificationFailed

    /// A certificate (or CertificateVerify) was presented but no public key was
    /// available to verify possession — fail closed.
    case certificateVerificationFailed

    /// The server Finished verify_data did not match (MAC mismatch).
    case finishedVerificationFailed

    /// A required secret was not available for a derivation step (internal
    /// invariant violation).
    case missingSecret

    /// The wire message failed to parse or re-encode.
    case wire(TLSWireError)

    /// A key-schedule derivation failed (e.g. an out-of-order transition or an
    /// HKDF bound violation).
    case keySchedule(TLSKeyScheduleError)

    /// A CertificateVerify signature-seam failure (an unsupported scheme or a
    /// public-key import failure).
    case signature(TLSSignatureCoreError)
}

/// A compact, Embedded-clean tag identifying the FSM state an unexpected message
/// arrived in. Carries no Foundation/`String` payload so the error stays
/// Embedded-clean and `Equatable`.
public enum TLSAuthStateTag: Sendable, Equatable {
    case waitEncryptedExtensions
    case waitCertificateOrCertificateRequest
    case waitCertificate
    case waitCertificateVerify
    case waitFinished
    case connected
}

/// A compact tag identifying a missing handshake extension.
public enum TLSAuthExtensionTag: Sendable, Equatable {
    case quicTransportParameters
}
