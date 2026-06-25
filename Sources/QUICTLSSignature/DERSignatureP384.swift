// DERSignatureP384.swift
// ECDSA over P-384 with **DER** signatures for the TLS 1.3 CertificateVerify wire
// (RFC 8446 §4.4.3), backed by the shared `DefaultCryptoProvider.P384Signature`
// (host swift-crypto / Embedded BoringSSL). See ``DERSignatureP256`` for the
// DER-vs-raw rationale; this is the 48-byte-scalar counterpart.
//
// Dual-build (host + Embedded): no Foundation, no `any`, no swift-crypto.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto   // DefaultCryptoProvider
// The backend module makes `DefaultCryptoProvider.P384Signature`'s nested key types
// nameable here (matching `DefaultCryptoProvider`'s own backend selection).
#if hasFeature(Embedded)
import P2PCryptoEmbedded
#else
import P2PCryptoFoundation
#endif

/// ECDSA over P-384 for the QUIC TLS handshake (DER signatures). Conforms
/// `P2PCoreCrypto.SignatureScheme`; wraps `DefaultCryptoProvider.P384Signature`.
public enum DERSignatureP384: P2PCoreCrypto.SignatureScheme {
    /// The P-384 coordinate width; a raw ECDSA signature is `2 * scalarLength` bytes.
    private static var scalarLength: Int { 48 }

    fileprivate typealias Base = DefaultCryptoProvider.P384Signature

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
