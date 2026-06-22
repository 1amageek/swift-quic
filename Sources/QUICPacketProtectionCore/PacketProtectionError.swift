/// Typed errors for the Embedded-clean QUIC packet-protection core.
///
/// Embedded-clean: no Foundation, no `any`. AEAD/key-derivation failures from the
/// `CryptoProvider` seam (``P2PCoreCrypto/CryptoError``) are surfaced via
/// ``crypto(_:)`` rather than swallowed — there is **no silent fallback**: an AEAD
/// open failure throws ``crypto(_:)`` carrying ``P2PCoreCrypto/CryptoError/authenticationFailure``,
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

    /// A primitive behind the `CryptoProvider`/`HeaderProtectionProvider` seam
    /// failed. Wraps the typed ``P2PCoreCrypto/CryptoError`` (e.g. an AEAD tag
    /// mismatch is `.crypto(.authenticationFailure)`).
    case crypto(CryptoError)
}
