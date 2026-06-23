/// TLS 1.3 protocol constants (RFC 8446).
///
/// Pure value data shared by the handshake message/extension wire codecs.
/// Embedded-clean: the HelloRetryRequest sentinel random is a `[UInt8]` (the
/// `QUICCrypto` adapter exposes a `Data` view for unchanged call sites).

public enum TLSConstants {
    /// TLS 1.3 version (0x0304)
    public static let version13: UInt16 = 0x0304

    /// TLS 1.2 version for legacy compatibility (0x0303)
    public static let legacyVersion: UInt16 = 0x0303

    /// Random bytes length
    public static let randomLength = 32

    /// Session ID max length
    public static let sessionIDMaxLength = 32

    /// Verify data length for Finished message (SHA-256)
    public static let verifyDataLength = 32

    /// HelloRetryRequest magic random value (SHA-256 of "HelloRetryRequest")
    public static let helloRetryRequestRandom: [UInt8] = [
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
    ]
}
