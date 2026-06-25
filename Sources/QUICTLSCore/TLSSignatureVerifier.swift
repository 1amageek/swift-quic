/// TLS 1.3 CertificateVerify signature verification (RFC 8446 §4.4.3),
/// Embedded-clean.
///
/// Builds the CertificateVerify signed input —
/// `64 * 0x20 || context-string || 0x00 || Transcript-Hash` — via
/// ``CertificateVerify/constructSignatureContentBytes(transcriptHash:isServer:)``
/// and verifies the signature through the ``P2PCoreCrypto/SignatureScheme`` seam
/// instead of swift-crypto. The verifier takes the *raw public-key bytes* (already
/// extracted from the certificate/SPKI by the adapter's X509 layer) plus the
/// algorithm, so the core never touches ASN.1 / X509.
///
/// The signature scheme selects the seam scheme via a closed `switch` on
/// ``SignatureScheme``; schemes outside ECDSA-P256 / ECDSA-P384 / Ed25519 (RSA,
/// Ed448, P-521) throw ``TLSSignatureCoreError/unsupportedScheme`` and stay in the
/// adapter (no silent fallback).
///
/// `verify` returns `Bool`: an invalid signature is an explicit `false`, **never**
/// a silent accept. It throws only ``TLSSignatureCoreError/unsupportedScheme`` for
/// a scheme the seam cannot express (a configuration error, surfaced loudly), or
/// ``TLSSignatureCoreError/crypto`` if importing the public key fails.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = QUICCryptoProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

/// TLS 1.3 CertificateVerify verification parameterised by the crypto seam.
public enum TLSSignatureVerifier<C: CryptoProvider> {

    /// Verifies a CertificateVerify signature over the reconstructed signed input.
    ///
    /// - Parameters:
    ///   - signature: The wire `signature` field from the CertificateVerify message
    ///     (DER-encoded for ECDSA, raw for Ed25519, per the provider's encoding).
    ///   - algorithm: The CertificateVerify `algorithm` field.
    ///   - publicKeyBytes: The peer public-key bytes the adapter extracted from the
    ///     certificate (x963 for the NIST curves, raw for Ed25519).
    ///   - transcriptHash: The handshake transcript hash up to (not including) the
    ///     CertificateVerify message.
    ///   - isServer: `true` for a server CertificateVerify, `false` for a client one
    ///     (selects the RFC 8446 context string).
    /// - Returns: `true` iff the signature is valid; `false` on any signature
    ///   mismatch (explicit, never silent).
    /// - Throws: ``TLSSignatureCoreError/unsupportedScheme`` for a non-seam scheme,
    ///   or ``TLSSignatureCoreError/crypto`` if the public key cannot be imported.
    public static func verify(
        signature: Span<UInt8>,
        algorithm: SignatureScheme,
        publicKeyBytes: Span<UInt8>,
        transcriptHash: Span<UInt8>,
        isServer: Bool
    ) throws(TLSSignatureCoreError) -> Bool {
        let transcript = transcriptHash.providerArrayCore()
        let content = CertificateVerify.constructSignatureContentBytes(
            transcriptHash: transcript,
            isServer: isServer
        )
        switch algorithm {
        case .ecdsa_secp256r1_sha256:
            return try verify(
                scheme: C.P256Signature.self,
                signature: signature,
                content: content.span,
                publicKeyBytes: publicKeyBytes
            )
        case .ecdsa_secp384r1_sha384:
            return try verify(
                scheme: C.P384Signature.self,
                signature: signature,
                content: content.span,
                publicKeyBytes: publicKeyBytes
            )
        case .ed25519:
            return try verify(
                scheme: C.Ed25519.self,
                signature: signature,
                content: content.span,
                publicKeyBytes: publicKeyBytes
            )
        case .ecdsa_secp521r1_sha512,
             .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512,
             .ed448,
             .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512:
            throw .unsupportedScheme
        }
    }

    private static func verify<S: P2PCoreCrypto.SignatureScheme>(
        scheme: S.Type,
        signature: Span<UInt8>,
        content: Span<UInt8>,
        publicKeyBytes: Span<UInt8>
    ) throws(TLSSignatureCoreError) -> Bool {
        let verifyingKey: S.VerifyingKey
        do {
            verifyingKey = try S.verifyingKey(rawRepresentation: publicKeyBytes)
        } catch {
            throw .crypto(error)
        }
        return S.isValid(signature: signature, for: content, with: verifyingKey)
    }
}
