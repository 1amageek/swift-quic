// DERSignatureP384.swift
// ECDSA over P-384 with **DER** signatures for the TLS 1.3 CertificateVerify wire
// (RFC 8446 §4.4.3), backed by the shared `DefaultCryptoProvider.P384Signature`
// from the common swift-crypto backend. See ``DERSignatureP256`` for the
// DER-vs-raw rationale; this is the 48-byte-scalar counterpart.
//
// Dual-build (host + Embedded): no Foundation, no `any`, no swift-crypto.

import P2PCoreBytes
import P2PCoreCrypto
import P2PCrypto   // DefaultCryptoProvider
/// ECDSA over P-384 for the QUIC TLS handshake (DER signatures). Conforms
/// `P2PCoreCrypto.SignatureScheme`; wraps `DefaultCryptoProvider.P384Signature`.
public enum DERSignatureP384: P2PCoreCrypto.SignatureScheme {
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
        // The shared swift-ssl backend already emits RFC 8446 DER. Re-encoding
        // it here would interpret the DER sequence as a raw r || s value.
        return try Base.sign(message, with: signingKey.inner)
    }

    public static func isValid(
        signature: Span<UInt8>,
        for message: Span<UInt8>,
        with verifyingKey: VerifyingKey
    ) -> Bool {
        return Base.isValid(signature: signature, for: message, with: verifyingKey.inner)
    }
}
