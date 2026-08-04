// QUICTLSSignatureProvider.swift
// The crypto provider that drives the libp2p-over-QUIC TLS 1.3 handshake
// signature path. The canonical swift-ssl P-256 TLS scheme emits DER directly;
// the raw P-256 scheme is a separate capability used by Noise and identity
// proofs. Keeping these as distinct associated types prevents a wire-format
// conversion from being accidentally applied twice.
//
// Ed25519 stays RAW: the libp2p RPK extension's proof-of-possession is raw Ed25519
// over the SPKI (the libp2p-tls spec encoding) — it must NOT be DER-wrapped.
//
// The existing host-only ``QUICCryptoProvider`` (Foundation + swift-crypto) serves
// the host QUICCrypto adapter; this provider is the dual-build (host + Embedded)
// counterpart for the seam-driven `[UInt8]` handshake path. It resolves the same
// backend in each build because it inherits from ``DefaultCryptoProvider``.

import P2PCrypto
import P2PCoreCrypto
import P2PCoreBytes
/// The crypto provider the libp2p-over-QUIC TLS handshake driver specialises at.
/// Identical to ``DefaultCryptoProvider`` except ECDSA signatures are DER-encoded
/// for the TLS CertificateVerify + X.509 leaf wire (RFC 8446 §4.4.3).
public enum QUICTLSSignatureProvider: CryptoProvider {
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

    // Signatures — Ed25519 and P-256 are supplied by the canonical backend.
    // P-256 is DER for TLS; RawP256Signature is P1363 for non-TLS protocols.
    public typealias Ed25519       = DefaultCryptoProvider.Ed25519
    public typealias P256Signature = DefaultCryptoProvider.P256Signature
    public typealias P384Signature = DefaultCryptoProvider.P384Signature
    public typealias RawP256Signature = DefaultCryptoProvider.RawP256Signature
    public typealias RawP384Signature = DefaultCryptoProvider.RawP384Signature

    // Ambient capabilities — inherited.
    public typealias Random           = DefaultCryptoProvider.Random
    public typealias Clock            = DefaultCryptoProvider.Clock
    public typealias HeaderProtection = DefaultCryptoProvider.HeaderProtection

    // AEAD factories — forward to the shared provider.
    @inline(__always)
    public static func makeAESGCM128(key: Span<UInt8>) throws(CryptoError) -> AESGCM128 {
        try DefaultCryptoProvider.makeAESGCM128(key: key)
    }
    @inline(__always)
    public static func makeAESGCM256(key: Span<UInt8>) throws(CryptoError) -> AESGCM256 {
        try DefaultCryptoProvider.makeAESGCM256(key: key)
    }
    @inline(__always)
    public static func makeChaChaPoly(key: Span<UInt8>) throws(CryptoError) -> ChaChaPoly {
        try DefaultCryptoProvider.makeChaChaPoly(key: key)
    }

    // Ambient singletons — forward to the shared provider.
    public static var random: Random { DefaultCryptoProvider.random }
    public static var clock:  Clock  { DefaultCryptoProvider.clock }
}
