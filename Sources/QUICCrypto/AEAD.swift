/// QUIC AEAD (Authenticated Encryption with Associated Data)
///
/// QUIC uses AES-128-GCM or ChaCha20-Poly1305 for packet protection.
/// This implementation provides AES-128-GCM.

import Foundation
import Crypto
import QUICCore

#if canImport(CommonCrypto)
import CommonCrypto
#endif

// MARK: - AES-128 Header Protection

/// AES-128 based header protection (RFC 9001 Section 5.4.3)
public struct AES128HeaderProtection: HeaderProtection, Sendable {
    private let key: SymmetricKey

    /// Creates AES-128 header protection with the given key
    /// - Parameter key: The header protection key (16 bytes)
    public init(key: SymmetricKey) {
        self.key = key
    }

    public func mask(sample: Data) throws -> Data {
        guard sample.count >= 16 else {
            throw CryptoError.insufficientSample(expected: 16, actual: sample.count)
        }
        return try aesECBEncrypt(key: key, block: sample.prefix(16))
    }
}

// MARK: - AES-128-GCM Opener

/// AES-128-GCM packet opener (decryption)
public struct AES128GCMOpener: PacketOpener, Sendable {
    private let key: SymmetricKey
    private let iv: Data
    private let headerProtection: AES128HeaderProtection

    /// AES-128-GCM requires 12-byte IV
    public static let ivLength = 12

    /// Creates an AES-128-GCM opener
    /// - Parameters:
    ///   - key: The packet protection key (16 bytes)
    ///   - iv: The packet protection IV (12 bytes)
    ///   - hp: The header protection key (16 bytes)
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        self.key = key
        self.iv = iv
        self.headerProtection = AES128HeaderProtection(key: hp)
    }

    /// Creates an opener from key material
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(keyMaterial: KeyMaterial) throws {
        try self.init(key: keyMaterial.key, iv: keyMaterial.iv, hp: keyMaterial.hp)
    }

    public func open(ciphertext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        // Construct nonce: IV XOR packet number (padded to 12 bytes)
        let nonce = constructNonce(iv: iv, packetNumber: packetNumber)

        // Separate ciphertext and tag (last 16 bytes)
        guard ciphertext.count >= 16 else {
            throw QUICError.decryptionFailed
        }

        let encryptedData = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)

        // Decrypt using AES-GCM
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: encryptedData,
            tag: tag
        )

        let plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: header)
        return plaintext
    }

    public func removeHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        // Generate mask using AES-ECB
        let mask = try headerProtection.mask(sample: sample)

        // For long header: mask lower 4 bits of first byte
        // For short header: mask lower 5 bits of first byte
        let isLongHeader = (firstByte & 0x80) != 0
        let firstByteMask: UInt8 = isLongHeader ? 0x0F : 0x1F

        let unprotectedFirstByte = firstByte ^ (mask[0] & firstByteMask)

        // Unmask packet number bytes
        var unprotectedPN = Data(capacity: packetNumberBytes.count)
        for i in 0..<packetNumberBytes.count {
            unprotectedPN.append(packetNumberBytes[i] ^ mask[i + 1])
        }

        return (unprotectedFirstByte, unprotectedPN)
    }
}

// MARK: - AES-128-GCM Sealer

/// AES-128-GCM packet sealer (encryption)
public struct AES128GCMSealer: PacketSealer, Sendable {
    private let key: SymmetricKey
    private let iv: Data
    private let headerProtection: AES128HeaderProtection

    /// AES-128-GCM requires 12-byte IV
    public static let ivLength = 12

    /// Creates an AES-128-GCM sealer
    /// - Parameters:
    ///   - key: The packet protection key (16 bytes)
    ///   - iv: The packet protection IV (12 bytes)
    ///   - hp: The header protection key (16 bytes)
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(key: SymmetricKey, iv: Data, hp: SymmetricKey) throws {
        guard iv.count == Self.ivLength else {
            throw CryptoError.invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        self.key = key
        self.iv = iv
        self.headerProtection = AES128HeaderProtection(key: hp)
    }

    /// Creates a sealer from key material
    /// - Throws: CryptoError.invalidIVLength if IV is not 12 bytes
    public init(keyMaterial: KeyMaterial) throws {
        try self.init(key: keyMaterial.key, iv: keyMaterial.iv, hp: keyMaterial.hp)
    }

    public func seal(plaintext: Data, packetNumber: UInt64, header: Data) throws -> Data {
        // Construct nonce: IV XOR packet number (padded to 12 bytes)
        let nonce = constructNonce(iv: iv, packetNumber: packetNumber)

        // Encrypt using AES-GCM
        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: key,
            nonce: AES.GCM.Nonce(data: nonce),
            authenticating: header
        )

        // Return ciphertext + tag
        return sealedBox.ciphertext + sealedBox.tag
    }

    public func applyHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        // Generate mask using AES-ECB
        let mask = try headerProtection.mask(sample: sample)

        // For long header: mask lower 4 bits of first byte
        // For short header: mask lower 5 bits of first byte
        let isLongHeader = (firstByte & 0x80) != 0
        let firstByteMask: UInt8 = isLongHeader ? 0x0F : 0x1F

        let protectedFirstByte = firstByte ^ (mask[0] & firstByteMask)

        // Mask packet number bytes
        var protectedPN = Data(capacity: packetNumberBytes.count)
        for i in 0..<packetNumberBytes.count {
            protectedPN.append(packetNumberBytes[i] ^ mask[i + 1])
        }

        return (protectedFirstByte, protectedPN)
    }
}

// MARK: - Helper Functions

/// Constructs a nonce from IV and packet number
/// nonce = iv XOR (packet_number padded to 12 bytes, left-padded with zeros)
///
/// - Precondition: iv.count == 12 (validated at init time)
@inline(__always)
private func constructNonce(iv: Data, packetNumber: UInt64) -> Data {
    var nonce = iv

    // XOR the last 8 bytes of the IV with the packet number (big-endian byte order)
    nonce.withUnsafeMutableBytes { buffer in
        let ptr = buffer.baseAddress!.assumingMemoryBound(to: UInt8.self)
        let offset = buffer.count - 8

        // Unroll the loop for performance (packet number is always 8 bytes)
        ptr[offset + 0] ^= UInt8(truncatingIfNeeded: packetNumber >> 56)
        ptr[offset + 1] ^= UInt8(truncatingIfNeeded: packetNumber >> 48)
        ptr[offset + 2] ^= UInt8(truncatingIfNeeded: packetNumber >> 40)
        ptr[offset + 3] ^= UInt8(truncatingIfNeeded: packetNumber >> 32)
        ptr[offset + 4] ^= UInt8(truncatingIfNeeded: packetNumber >> 24)
        ptr[offset + 5] ^= UInt8(truncatingIfNeeded: packetNumber >> 16)
        ptr[offset + 6] ^= UInt8(truncatingIfNeeded: packetNumber >> 8)
        ptr[offset + 7] ^= UInt8(truncatingIfNeeded: packetNumber)
    }

    return nonce
}

/// Performs single-block AES-ECB encryption for header protection
/// - Parameters:
///   - key: The AES key (16 bytes for AES-128)
///   - block: The 16-byte block to encrypt
/// - Returns: First 5 bytes of the encrypted block (the mask)
/// - Throws: CryptoError if encryption fails or platform not supported
private func aesECBEncrypt(key: SymmetricKey, block: Data) throws -> Data {
    #if canImport(CommonCrypto)
    // Use CommonCrypto for single-block AES-ECB encryption
    var output = Data(count: 16)
    var outputLength: size_t = 0

    let status = key.withUnsafeBytes { keyBytes in
        block.withUnsafeBytes { blockBytes in
            output.withUnsafeMutableBytes { outputBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, keyBytes.count,
                    nil,  // No IV for ECB
                    blockBytes.baseAddress, 16,
                    outputBytes.baseAddress, 16,
                    &outputLength
                )
            }
        }
    }

    guard status == kCCSuccess else {
        throw CryptoError.headerProtectionFailed
    }

    return Data(output.prefix(5))
    #else
    // Non-Apple platforms require alternative implementation
    // Options:
    // 1. Use BoringSSL/OpenSSL bindings
    // 2. Software AES implementation
    // 3. Link against a crypto library that provides AES-ECB
    //
    // For now, throw an error indicating the limitation.
    // This is a compile-time known limitation for non-Apple platforms.
    throw CryptoError.unsupportedPlatform(
        "AES-ECB header protection requires CommonCrypto (Apple platforms). " +
        "For Linux support, link against a crypto library providing AES-ECB."
    )
    #endif
}
