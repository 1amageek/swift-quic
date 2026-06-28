// QUICTLSSignatureProvider.swift
// The crypto provider that drives the libp2p-over-QUIC TLS 1.3 handshake SIGNATURE
// path. It is the shared ``DefaultCryptoProvider`` for every primitive EXCEPT the
// two ECDSA signature schemes, which are overridden with the DER-encoded wrappers
// (``DERSignatureP256`` / ``DERSignatureP384``) the TLS wire mandates.
//
// WHY: the shared provider emits ECDSA signatures in *raw* `r || s` form (correct
// for Noise / libp2p), whereas the TLS 1.3 CertificateVerify (RFC 8446 §4.4.3) and
// the self-signed X.509 leaf signature require *DER* `SEQUENCE { INTEGER r, INTEGER
// s }`. Emitting raw ECDSA on the TLS wire silently breaks interop with
// go-libp2p / rust-libp2p QUIC peers. This composite fixes ONLY the ECDSA signature
// encoding; AEAD / packet-protection / hashing / HKDF / x25519 / Ed25519 / entropy
// are inherited unchanged from the shared provider (so handshake keys are
// byte-identical to a `DefaultCryptoProvider`-driven engine).
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

    // Signatures — Ed25519 inherited (raw 64-byte, identical wire form, libp2p PoP);
    // ECDSA OVERRIDDEN to DER for the TLS CertificateVerify + X.509 leaf wire.
    public typealias Ed25519       = DefaultCryptoProvider.Ed25519
    public typealias P256Signature = DERSignatureP256
    public typealias P384Signature = DERSignatureP384

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
