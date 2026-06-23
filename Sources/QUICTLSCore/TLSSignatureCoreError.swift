/// Typed errors raised by the Embedded-clean TLS 1.3 CertificateVerify
/// sign/verify operations (RFC 8446 §4.4.3).
///
/// Carries the underlying ``P2PCoreCrypto/CryptoError`` for seam failures rather
/// than swallowing them (no silent fallback). `unsupportedScheme` covers signature
/// schemes the seam does not express (RSA-PSS / RSA-PKCS1 / Ed448 / P-521); those
/// stay in the adapter.
///
/// Verification itself never throws this for a bad signature — it returns `Bool` so
/// an invalid signature is an explicit `false`, never a silent accept.
///
/// Embedded-clean: no Foundation, no `any`, closed enum, typed throws.

import P2PCoreCrypto

/// Errors from `QUICTLSCore` CertificateVerify sign/verify operations.
public enum TLSSignatureCoreError: Error, Equatable, Sendable {
    /// The signature scheme is not one of ECDSA-P256 / ECDSA-P384 / Ed25519
    /// (the only schemes expressible through the signature seam).
    case unsupportedScheme

    /// A crypto-seam signing primitive failed (key import or signing).
    case crypto(CryptoError)
}
