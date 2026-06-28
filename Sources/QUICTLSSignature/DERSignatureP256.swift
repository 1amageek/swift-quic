// DERSignatureP256.swift
// ECDSA over P-256 with **DER** signatures for the TLS 1.3 CertificateVerify wire
// (RFC 8446 §4.4.3) and the libp2p X.509 RPK self-signature, backed by the shared
// `DefaultCryptoProvider.P256Signature` (host swift-crypto / Embedded BoringSSL).
//
// The shared scheme emits raw `r || s`; this wrapper DER-encodes via
// ``ECDSADERConversion`` (byte-identical to the host `QUICDERSignatureP256` /
// CryptoKit `derRepresentation`). Keys keep the SAME raw representations as the
// underlying scheme: a 32-byte scalar (signing) and a 65-byte X9.62 uncompressed
// point (verifying), so a leaf SPKI parsed elsewhere imports unchanged.
//
// Dual-build (host + Embedded): no Foundation, no `any`, no swift-crypto — it only
// composes the shared seam scheme with the Embedded-clean DER codec.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto   // DefaultCryptoProvider
/// ECDSA over P-256 for the QUIC TLS handshake (DER signatures). Conforms
/// `P2PCoreCrypto.SignatureScheme`; wraps `DefaultCryptoProvider.P256Signature`.
public enum DERSignatureP256: P2PCoreCrypto.SignatureScheme {
    /// The P-256 coordinate width; a raw ECDSA signature is `2 * scalarLength` bytes.
    private static var scalarLength: Int { 32 }

    fileprivate typealias Base = DefaultCryptoProvider.P256Signature

    public struct SigningKey: Sendable {
        fileprivate let inner: Base.SigningKey
    }

    public struct VerifyingKey: Sendable {
        fileprivate let inner: Base.VerifyingKey
    }

    public static func generateSigningKey() throws(CryptoError) -> SigningKey {
        SigningKey(inner: try Base.generateSigningKey())
    }

    public static func signingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> SigningKey {
        SigningKey(inner: try Base.signingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(rawRepresentation: Span<UInt8>) throws(CryptoError) -> VerifyingKey {
        VerifyingKey(inner: try Base.verifyingKey(rawRepresentation: rawRepresentation))
    }

    public static func verifyingKey(for signingKey: SigningKey) -> VerifyingKey {
        VerifyingKey(inner: Base.verifyingKey(for: signingKey.inner))
    }

    public static func rawRepresentation(of signingKey: SigningKey) -> [UInt8] {
        Base.rawRepresentation(of: signingKey.inner)
    }

    public static func rawRepresentation(of verifyingKey: VerifyingKey) -> [UInt8] {
        Base.rawRepresentation(of: verifyingKey.inner)
    }

    public static func sign(_ message: Span<UInt8>, with signingKey: SigningKey) throws(CryptoError) -> [UInt8] {
        let raw = try Base.sign(message, with: signingKey.inner)
        return try ECDSADERConversion.encode(raw: raw, scalarLength: scalarLength)
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        guard let raw = ECDSADERConversion.decode(
            der: signature.tlsSignatureArray(), scalarLength: scalarLength
        ) else {
            return false
        }
        return Base.isValid(signature: raw.span, for: message, with: verifyingKey.inner)
    }
}
