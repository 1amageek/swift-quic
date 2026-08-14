import NetworkingCore
import SSLCrypto

/// A keyed QUIC packet protector for one authenticated cipher.
///
/// The class is an immutable owner around the move-only cipher key schedule.
/// Sharing it is safe because packet operations only borrow that schedule. The
/// packet IV and header-protection key remain owned for exactly the lifetime of
/// this protector and are never exposed as mutable storage.
public final class PacketProtector<A: ~Copyable & AuthenticatedCipher>: Sendable {
    private let aead: A
    private let iv: [UInt8]
    private let hpKey: [UInt8]
    private let usesAESHeaderProtection: Bool

    public static var ivLength: Int { 12 }
    public static var tagLength: Int { A.tagByteCount }

    public init(
        aead: consuming A,
        iv: [UInt8],
        hpKey: [UInt8],
        usesAESHeaderProtection: Bool
    ) throws(PacketProtectionError) {
        guard iv.count == Self.ivLength else {
            throw .invalidIVLength(expected: Self.ivLength, actual: iv.count)
        }
        self.aead = aead
        self.iv = iv
        self.hpKey = hpKey
        self.usesAESHeaderProtection = usesAESHeaderProtection
    }

    @inline(__always)
    public func nonce(packetNumber: UInt64) -> [UInt8] {
        var nonce = iv
        let offset = nonce.count - 8
        nonce[offset + 0] ^= UInt8(truncatingIfNeeded: packetNumber >> 56)
        nonce[offset + 1] ^= UInt8(truncatingIfNeeded: packetNumber >> 48)
        nonce[offset + 2] ^= UInt8(truncatingIfNeeded: packetNumber >> 40)
        nonce[offset + 3] ^= UInt8(truncatingIfNeeded: packetNumber >> 32)
        nonce[offset + 4] ^= UInt8(truncatingIfNeeded: packetNumber >> 24)
        nonce[offset + 5] ^= UInt8(truncatingIfNeeded: packetNumber >> 16)
        nonce[offset + 6] ^= UInt8(truncatingIfNeeded: packetNumber >> 8)
        nonce[offset + 7] ^= UInt8(truncatingIfNeeded: packetNumber)
        return nonce
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        packetNumber: UInt64,
        header: Span<UInt8>
    ) throws(PacketProtectionError) -> [UInt8] {
        let nonceBytes = nonce(packetNumber: packetNumber)
        var output = [UInt8](repeating: 0, count: plaintext.count + A.tagByteCount)
        do {
            var destination = output.mutableSpan
            try aead.seal(
                plaintext: plaintext,
                authenticatedData: header,
                nonce: nonceBytes.span,
                into: &destination
            )
            return output
        } catch let error {
            throw .aead(error)
        }
    }

    public func open(
        _ ciphertext: Span<UInt8>,
        packetNumber: UInt64,
        header: Span<UInt8>
    ) throws(PacketProtectionError) -> [UInt8] {
        guard ciphertext.count >= Self.tagLength else {
            throw .ciphertextTooShort(minimum: Self.tagLength, actual: ciphertext.count)
        }
        let nonceBytes = nonce(packetNumber: packetNumber)
        var output = [UInt8](repeating: 0, count: ciphertext.count - A.tagByteCount)
        do {
            var destination = output.mutableSpan
            try aead.open(
                ciphertextAndTag: ciphertext,
                authenticatedData: header,
                nonce: nonceBytes.span,
                into: &destination
            )
            return output
        } catch let error {
            throw .aead(error)
        }
    }

    public func headerProtectionMask(sample: Span<UInt8>) throws(PacketProtectionError) -> [UInt8] {
        guard sample.count >= 16 else {
            throw .insufficientSample(expected: 16, actual: sample.count)
        }
        // Retain the immutable COW owner locally for the complete synchronous
        // borrow. No bytes are copied and neither span escapes this method.
        let key = hpKey
        let exactSample = sample.extracting(0..<16)
        do throws(AEADError) {
            if usesAESHeaderProtection {
                return Array(try QUICHeaderProtection.aes(key: key.span, sample: exactSample))
            }
            return Array(try QUICHeaderProtection.chaCha20(key: key.span, sample: exactSample))
        } catch let error {
            throw .headerProtection(error)
        }
    }

    public func applyHeaderProtection(
        sample: Span<UInt8>,
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let mask = try headerProtectionMask(sample: sample)
        return Self.applyMask(mask, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
    }

    public func removeHeaderProtection(
        sample: Span<UInt8>,
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let mask = try headerProtectionMask(sample: sample)
        return Self.applyMask(mask, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
    }

    @inline(__always)
    static func applyMask(
        _ mask: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let isLongHeader = (firstByte & 0x80) != 0
        let firstByteMask: UInt8 = isLongHeader ? 0x0F : 0x1F
        let maskedFirstByte = firstByte ^ (mask[0] & firstByteMask)

        var maskedPN = [UInt8]()
        maskedPN.reserveCapacity(packetNumberBytes.count)
        for index in packetNumberBytes.indices {
            maskedPN.append(packetNumberBytes[index] ^ mask[index + 1])
        }
        return (maskedFirstByte, maskedPN)
    }
}
