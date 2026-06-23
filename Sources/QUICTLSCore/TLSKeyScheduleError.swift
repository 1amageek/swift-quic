/// Typed errors for the Embedded-clean TLS 1.3 key schedule (RFC 8446 §7.1).
///
/// These are protocol-correctness errors: an out-of-order key-schedule transition
/// (deriving handshake secrets before the early secret, application secrets before
/// the handshake secret, etc.) or a crypto-seam failure (an HKDF length bound
/// violation) MUST be surfaced to the caller, never silently substituted with a
/// default secret.
///
/// Embedded-clean: no Foundation, no `any`. A closed enum; never silently swallowed.
import P2PCoreCrypto

/// Errors from TLS 1.3 key-schedule operations.
public enum TLSKeyScheduleError: Error, Sendable, Equatable {
    /// The key schedule is in the wrong state for the requested derivation
    /// (e.g. handshake secrets requested before the early secret was derived).
    case invalidState(KeyScheduleStage)

    /// A `CryptoProvider.KeyDerivation` call failed (e.g. an HKDF-Expand length
    /// bound violation). Carries the underlying seam error.
    case crypto(CryptoError)
}

/// The stage the key schedule must be in for a derivation to be valid.
///
/// Surfaced by ``TLSKeyScheduleError/invalidState(_:)`` so the caller learns which
/// transition was attempted out of order.
public enum KeyScheduleStage: Sendable, Equatable {
    case initial
    case earlySecret
    case handshakeSecret
    case masterSecret
}
