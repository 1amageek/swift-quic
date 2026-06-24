/// The QUIC TLS crypto provider — the unified ``P2PCrypto/DefaultCryptoProvider``
/// for every primitive except the two ECDSA signature schemes.
///
/// embedded-first-api.md §2.2 unifies the per-library `*FoundationProvider`s into a
/// single shared ``DefaultCryptoProvider``. QUIC adopts it wholesale for AEAD,
/// hashing, HKDF, HMAC, header protection, key agreement, Ed25519 signing, entropy
/// and the monotonic clock — bringing the shared provider's bulk-copy primitives.
///
/// The ONE exception is ECDSA: the shared `FoundationCryptoProvider` emits ECDSA
/// signatures in *raw* `r||s` form (correct for Noise/libp2p), whereas the TLS 1.3
/// CertificateVerify wire format (RFC 8446 §4.2.3) requires *DER*. Emitting raw
/// ECDSA on the QUIC TLS wire would silently break interop and is caught by
/// `KeyExchangeSignatureSeamDifferentialTests`. This composite therefore overrides
/// `P256Signature`/`P384Signature` with the DER schemes
/// (``QUICDERSignatureP256`` / ``QUICDERSignatureP384``) and inherits everything
/// else from the shared provider — preserving the CertificateVerify bytes
/// byte-identically while still unifying the rest of the crypto surface.
///
/// Both back ends are swift-crypto / CryptoKit, so the DER-vs-raw difference is the
/// only divergence; key import, hashing and verification are otherwise identical.

import P2PCrypto
import P2PCoreCrypto
// The concrete primitive types behind `DefaultCryptoProvider`'s associated types
// live in the backend module; importing it makes them nameable in the typealiases
// below. Mirror `DefaultCryptoProvider`'s own backend selection so this composite
// resolves to the same backend in each build (QUICCrypto is the host adapter, so
// in practice this is always the Foundation branch).
#if hasFeature(Embedded)
import P2PCryptoEmbedded
#else
import P2PCryptoFoundation
#endif

/// The crypto provider the QUIC TLS engine specialises at. Identical to
/// ``DefaultCryptoProvider`` except ECDSA signatures are DER-encoded for the TLS
/// CertificateVerify wire (RFC 8446 §4.2.3).
public enum QUICCryptoProvider: CryptoProvider {
    // AEAD — inherited from the shared provider.
    public typealias AESGCM128  = DefaultCryptoProvider.AESGCM128
    public typealias AESGCM256  = DefaultCryptoProvider.AESGCM256
    public typealias ChaChaPoly = DefaultCryptoProvider.ChaChaPoly

    // Hashes — inherited.
    public typealias SHA256 = DefaultCryptoProvider.SHA256
    public typealias SHA384 = DefaultCryptoProvider.SHA384

    // Key derivation — inherited (hash-bound by the same SHA256/SHA384).
    public typealias HKDFSHA256 = DefaultCryptoProvider.HKDFSHA256
    public typealias HKDFSHA384 = DefaultCryptoProvider.HKDFSHA384

    // Message authentication — inherited.
    public typealias HMACSHA1   = DefaultCryptoProvider.HMACSHA1
    public typealias HMACSHA256 = DefaultCryptoProvider.HMACSHA256
    public typealias HMACSHA384 = DefaultCryptoProvider.HMACSHA384

    // Key agreement — inherited (shared secrets are raw bytes, format-identical).
    public typealias X25519        = DefaultCryptoProvider.X25519
    public typealias P256Agreement = DefaultCryptoProvider.P256Agreement
    public typealias P384Agreement = DefaultCryptoProvider.P384Agreement

    // Signatures — Ed25519 inherited (raw 64-byte, identical wire form);
    // ECDSA OVERRIDDEN to DER for the TLS CertificateVerify wire (RFC 8446 §4.2.3).
    public typealias Ed25519       = DefaultCryptoProvider.Ed25519
    public typealias P256Signature = QUICDERSignatureP256
    public typealias P384Signature = QUICDERSignatureP384

    // Ambient capabilities — inherited.
    public typealias Random           = DefaultCryptoProvider.Random
    public typealias Clock            = DefaultCryptoProvider.Clock
    public typealias HeaderProtection = DefaultCryptoProvider.HeaderProtection

    // AEAD factories — forward to the shared provider. Fully-qualify the thrown
    // error: QUICCrypto defines its own `CryptoError`, so the unqualified name here
    // would shadow `P2PCoreCrypto.CryptoError` (the protocol's error type).
    @inline(__always)
    public static func makeAESGCM128(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> AESGCM128 {
        try DefaultCryptoProvider.makeAESGCM128(key: key)
    }
    @inline(__always)
    public static func makeAESGCM256(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> AESGCM256 {
        try DefaultCryptoProvider.makeAESGCM256(key: key)
    }
    @inline(__always)
    public static func makeChaChaPoly(key: Span<UInt8>) throws(P2PCoreCrypto.CryptoError) -> ChaChaPoly {
        try DefaultCryptoProvider.makeChaChaPoly(key: key)
    }

    // Ambient singletons — forward to the shared provider.
    public static var random: Random { DefaultCryptoProvider.random }
    public static var clock:  Clock  { DefaultCryptoProvider.clock }
}
