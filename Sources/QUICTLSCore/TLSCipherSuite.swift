/// TLS 1.3 cipher suites (RFC 8446 §B.4).
///
/// The wire-level cipher-suite code point plus the AEAD/hash sizes each suite
/// implies. This is distinct from ``TLSCipherSuiteCore`` (the reduced
/// hash-only view the key schedule consumes): this enum is the value that
/// appears on the wire in ClientHello/ServerHello. It is pure value data and is
/// Embedded-clean (no Foundation, no `any`).

public enum CipherSuite: UInt16, Sendable, CaseIterable {
    case tls_aes_128_gcm_sha256 = 0x1301
    case tls_aes_256_gcm_sha384 = 0x1302
    case tls_chacha20_poly1305_sha256 = 0x1303

    /// Key length in bytes.
    public var keyLength: Int {
        switch self {
        case .tls_aes_128_gcm_sha256: return 16
        case .tls_aes_256_gcm_sha384: return 32
        case .tls_chacha20_poly1305_sha256: return 32
        }
    }

    /// IV length in bytes (all TLS 1.3 cipher suites use 12 bytes).
    public var ivLength: Int { 12 }

    /// Hash output length in bytes.
    public var hashLength: Int {
        switch self {
        case .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256: return 32
        case .tls_aes_256_gcm_sha384: return 48
        }
    }
}
