/// TLS 1.3 CertificateVerify signing (RFC 8446 §4.4.3), Embedded-clean.
///
/// Builds the CertificateVerify signed input —
/// `64 * 0x20 || context-string || 0x00 || Transcript-Hash` — via
/// ``CertificateVerify/constructSignatureContentBytes(transcriptHash:isServer:)``
/// and signs it through the ``P2PCoreCrypto/SignatureScheme`` seam instead of
/// swift-crypto. The signer takes the *raw private-key bytes* plus the algorithm;
/// the resulting signature bytes go straight into the wire `signature` field
/// (DER-encoded for ECDSA, raw for Ed25519, per the provider's encoding).
///
/// The signature scheme selects the seam scheme via a closed `switch` on
/// ``SignatureScheme``; schemes outside ECDSA-P256 / ECDSA-P384 / Ed25519 throw
/// ``TLSSignatureCoreError/unsupportedScheme`` and stay in the adapter (no silent
/// fallback). A seam signing failure throws ``TLSSignatureCoreError/crypto`` —
/// never a fabricated signature.
///
/// ECDSA / Ed25519 signing is randomised, so two signatures over the same input
/// differ; both verify under the matching verifier. Correctness is asserted via
/// verify-roundtrip and cross-verification against the legacy path.
///
/// Generic over `C: CryptoProvider`; the adapter specialises at
/// `C = QUICCryptoProvider`. Embedded-clean: no Foundation, no `any`, no Mutex,
/// no swift-crypto, typed throws.

import P2PCoreBytes
import P2PCoreCrypto

/// TLS 1.3 CertificateVerify signing parameterised by the crypto seam.
public enum TLSSignatureSigner<C: CryptoProvider> {

    /// Signs the CertificateVerify signed input for `algorithm`.
    ///
    /// - Parameters:
    ///   - algorithm: The signature scheme (also written into the CertificateVerify
    ///     `algorithm` field).
    ///   - privateKeyBytes: The raw signing-key bytes (raw scalar for the NIST
    ///     curves, 32-byte seed for Ed25519).
    ///   - transcriptHash: The handshake transcript hash up to (not including) the
    ///     CertificateVerify message.
    ///   - isServer: `true` for a server CertificateVerify, `false` for a client one
    ///     (selects the RFC 8446 context string).
    /// - Returns: The signature bytes for the wire `signature` field.
    /// - Throws: ``TLSSignatureCoreError/unsupportedScheme`` for a non-seam scheme,
    ///   or ``TLSSignatureCoreError/crypto`` if the key cannot be imported or the
    ///   seam signing primitive fails (never a fabricated signature).
    public static func sign(
        algorithm: SignatureScheme,
        privateKeyBytes: Span<UInt8>,
        transcriptHash: Span<UInt8>,
        isServer: Bool
    ) throws(TLSSignatureCoreError) -> [UInt8] {
        let transcript = transcriptHash.providerArrayCore()
        let content = CertificateVerify.constructSignatureContentBytes(
            transcriptHash: transcript,
            isServer: isServer
        )
        switch algorithm {
        case .ecdsa_secp256r1_sha256:
            return try sign(
                scheme: C.P256Signature.self,
                content: content.span,
                privateKeyBytes: privateKeyBytes
            )
        case .ecdsa_secp384r1_sha384:
            return try sign(
                scheme: C.P384Signature.self,
                content: content.span,
                privateKeyBytes: privateKeyBytes
            )
        case .ed25519:
            return try sign(
                scheme: C.Ed25519.self,
                content: content.span,
                privateKeyBytes: privateKeyBytes
            )
        case .ecdsa_secp521r1_sha512,
             .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512,
             .ed448,
             .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512:
            throw .unsupportedScheme
        }
    }

    private static func sign<S: P2PCoreCrypto.SignatureScheme>(
        scheme: S.Type,
        content: Span<UInt8>,
        privateKeyBytes: Span<UInt8>
    ) throws(TLSSignatureCoreError) -> [UInt8] {
        do {
            let key = try S.signingKey(rawRepresentation: privateKeyBytes)
            return try S.sign(content, with: key)
        } catch {
            throw .crypto(error)
        }
    }
}
