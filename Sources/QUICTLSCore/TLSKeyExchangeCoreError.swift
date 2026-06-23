/// Typed errors raised by the Embedded-clean TLS 1.3 (EC)DHE key exchange
/// (RFC 8446 §4.2.8).
///
/// These are protocol-correctness errors: a negotiated group outside the DH
/// key-agreement seam (`x25519` / `secp256r1`), a wrong-length peer public key, or
/// a crypto-seam failure MUST be surfaced to the caller, never silently substituted
/// with an empty / garbage shared secret (no silent fallback).
///
/// Embedded-clean: no Foundation, no `any`, closed enum, typed throws.

import P2PCoreCrypto

/// Errors from `QUICTLSCore` (EC)DHE key-exchange operations.
public enum TLSKeyExchangeCoreError: Error, Equatable, Sendable {
    /// The named group is not one of X25519 / P-256 (the only groups QUIC's TLS 1.3
    /// expresses through the DH key-agreement seam).
    case unsupportedGroup

    /// The peer public key is not the expected wire length for the group.
    case invalidPublicKeyLength(expected: Int, actual: Int)

    /// A crypto-seam key-agreement primitive failed (e.g. an invalid peer point).
    case crypto(CryptoError)
}
