/// Typed errors for the Embedded-clean QUIC packet-protection core.
///
/// Embedded-clean: no Foundation, no `any`. AEAD/key-derivation failures from the
/// `CryptoProvider` seam (``P2PCoreCrypto/CryptoError``) retain the operation
/// that failed. There is **no silent fallback**: an AEAD open failure throws
/// ``aead(_:)`` carrying ``P2PCoreCrypto/CryptoError/authenticationFailure``,
/// never an empty/garbage plaintext.

import P2PCoreCrypto

/// Errors raised by ``PacketProtector`` / ``SuiteProtector``.
public enum PacketProtectionError: Error, Equatable, Sendable {
    /// The IV passed at construction time was not 12 bytes (RFC 9001 §5.3).
    case invalidIVLength(expected: Int, actual: Int)

    /// The header-protection sample was shorter than 16 bytes (RFC 9001 §5.4.2).
    case insufficientSample(expected: Int, actual: Int)

    /// The AEAD ciphertext was shorter than the 16-byte authentication tag.
    case ciphertextTooShort(minimum: Int, actual: Int)

    /// AEAD construction, sealing, or opening failed.
    case aead(CryptoError)

    /// Header-protection mask generation failed.
    case headerProtection(CryptoError)

    /// HKDF extraction or expansion failed while deriving packet keys.
    case keyDerivation(CryptoError)
}
