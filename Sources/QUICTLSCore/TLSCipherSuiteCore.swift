/// The cipher-suite parameters the TLS 1.3 key schedule needs (RFC 8446 §B.4),
/// reduced to the hash size that drives every HKDF call.
///
/// `QUICTLSCore` is Embedded-clean and must not depend on the QUICCrypto adapter's
/// `CipherSuite` enum (which carries Foundation-flavoured helpers). The key schedule
/// only ever branches on the hash function (SHA-256 vs SHA-384), so the core models
/// exactly that. The adapter maps its `CipherSuite` to this value type at the seam.
///
/// Embedded-clean: no Foundation, no `any`, no swift-crypto, no Mutex/ContinuousClock.

/// The hash function selected by a TLS 1.3 cipher suite.
///
/// TLS 1.3 (RFC 8446 §B.4) binds each cipher suite to a single hash: the AES-128-GCM
/// and ChaCha20-Poly1305 suites use SHA-256; AES-256-GCM uses SHA-384.
public enum TLSHashAlgorithm: Sendable, Equatable {
    case sha256
    case sha384

    /// Digest length in bytes (32 for SHA-256, 48 for SHA-384).
    public var digestLength: Int {
        switch self {
        case .sha256: return 32
        case .sha384: return 48
        }
    }
}

/// The minimal cipher-suite description the key schedule consumes: the hash
/// algorithm plus the AEAD key/iv lengths used for traffic-key derivation.
public struct TLSCipherSuiteCore: Sendable, Equatable {
    /// The hash function driving HKDF and the transcript.
    public let hash: TLSHashAlgorithm

    /// AEAD key length in bytes (16 for AES-128, 32 for AES-256 / ChaCha20).
    public let keyLength: Int

    /// AEAD IV length in bytes (always 12 for TLS 1.3 suites).
    public let ivLength: Int

    public init(hash: TLSHashAlgorithm, keyLength: Int, ivLength: Int = 12) {
        self.hash = hash
        self.keyLength = keyLength
        self.ivLength = ivLength
    }

    /// Hash output length in bytes (the secret length used throughout the schedule).
    public var hashLength: Int { hash.digestLength }

    // MARK: - Standard TLS 1.3 suites

    /// `TLS_AES_128_GCM_SHA256` (0x1301).
    public static let aes128GCMSHA256 = TLSCipherSuiteCore(hash: .sha256, keyLength: 16)

    /// `TLS_AES_256_GCM_SHA384` (0x1302).
    public static let aes256GCMSHA384 = TLSCipherSuiteCore(hash: .sha384, keyLength: 32)

    /// `TLS_CHACHA20_POLY1305_SHA256` (0x1303).
    public static let chacha20Poly1305SHA256 = TLSCipherSuiteCore(hash: .sha256, keyLength: 32)
}
