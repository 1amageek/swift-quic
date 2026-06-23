/// Typed errors for the Embedded-clean TLS 1.3 server handshake FSM
/// (``QUICServerHandshake``).
///
/// These are handshake-correctness and authentication errors for the server flight
/// (ClientHello through client Finished). Every failure is surfaced explicitly to
/// the caller (no silent fallback): an out-of-order message, a client
/// CertificateVerify signature mismatch, or a client Finished MAC mismatch fails the
/// handshake closed. The QUICCrypto adapter maps each case to the corresponding TLS
/// alert / `TLSHandshakeError` before converting it into a QUIC CONNECTION_CLOSE
/// frame.
///
/// Embedded-clean: no Foundation, no `any`. A closed enum; never silently swallowed.
import P2PCoreCrypto

/// Errors raised by the server handshake FSM.
public enum QUICServerHandshakeError: Error, Sendable, Equatable {
    /// A handshake message (or production request) arrived in a state where it is
    /// not permitted (e.g. a client Finished before the server flight was built, or
    /// a second HelloRetryRequest).
    case unexpectedMessage(QUICServerHandshakeStateTag)

    /// The client CertificateVerify proof-of-possession signature did not validate,
    /// the signature scheme did not match the client key, or the algorithm was not
    /// one the server offered in CertificateRequest.
    case signatureVerificationFailed

    /// The client Finished verify_data did not match (MAC mismatch).
    case finishedVerificationFailed

    /// A certificate verification key was required (the client presented a
    /// certificate) but none was available — fail closed.
    case missingClientVerificationKey

    /// The (EC)DHE key exchange failed (carries the seam error).
    case keyExchange(TLSKeyExchangeCoreError)

    /// A client CertificateVerify signature-seam failure (an unsupported scheme or a
    /// public-key import failure).
    case signature(TLSSignatureCoreError)

    /// The wire message failed to encode (carries the wire error).
    case wire(TLSWireError)

    /// A key-schedule derivation failed (e.g. an out-of-order transition or an HKDF
    /// bound violation).
    case keySchedule(TLSKeyScheduleError)

    /// An internal invariant was violated (e.g. a non-PSK handshake without a server
    /// Certificate, or a required secret missing).
    case internalInvariant(QUICServerHandshakeInvariantTag)
}

/// A compact, Embedded-clean tag identifying the FSM state an unexpected message
/// arrived in. Carries no Foundation/`String` payload so the error stays
/// Embedded-clean and `Equatable`.
public enum QUICServerHandshakeStateTag: Sendable, Equatable {
    case start
    case sentHelloRetryRequest
    case waitClientCertificate
    case waitClientCertificateVerify
    case waitFinished
    case connected
}

/// A compact tag naming an internal invariant violation in the server FSM.
public enum QUICServerHandshakeInvariantTag: Sendable, Equatable {
    /// A non-PSK handshake reached the CertificateVerify step without a server
    /// Certificate having been folded.
    case nonPSKMissingServerCertificate
    /// A required handshake secret was missing for a derivation step.
    case missingHandshakeSecret
    /// The server CertificateVerify was folded outside the build phase.
    case certificateVerifyFoldedOutOfOrder
    /// The server flight was finished outside the build phase.
    case flightFinishedOutOfOrder
}
