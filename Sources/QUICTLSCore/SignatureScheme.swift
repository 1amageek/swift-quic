/// TLS 1.3 signature schemes (RFC 8446 §4.2.3).
///
/// The wire-level code points for the signature_algorithms extension and the
/// CertificateVerify message. Pure value data; Embedded-clean (no Foundation,
/// no `any`).

public enum SignatureScheme: UInt16, Sendable {
    // ECDSA
    case ecdsa_secp256r1_sha256 = 0x0403
    case ecdsa_secp384r1_sha384 = 0x0503
    case ecdsa_secp521r1_sha512 = 0x0603

    // RSASSA-PSS with rsaEncryption OID
    case rsa_pss_rsae_sha256 = 0x0804
    case rsa_pss_rsae_sha384 = 0x0805
    case rsa_pss_rsae_sha512 = 0x0806

    // EdDSA
    case ed25519 = 0x0807
    case ed448 = 0x0808

    // RSASSA-PKCS1-v1_5 (for certificates only)
    case rsa_pkcs1_sha256 = 0x0401
    case rsa_pkcs1_sha384 = 0x0501
    case rsa_pkcs1_sha512 = 0x0601
}
