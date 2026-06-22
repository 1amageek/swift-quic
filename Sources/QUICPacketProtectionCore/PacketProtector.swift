/// The Embedded-clean generic QUIC packet protector (RFC 9001 §5).
///
/// `PacketProtector<C, A>` carries one keyed AEAD `A` plus the packet-protection
/// IV and the header-protection key, and performs:
/// - AEAD payload protection (`seal`/`open`) over the `CryptoProvider.AEAD` seam,
/// - header protection (`applyHeaderProtection`/`removeHeaderProtection`) over the
///   `CryptoProvider.HeaderProtection` (`HeaderProtectionProvider`) seam.
///
/// It is a `Sendable` value type (one per derived key) and replaces the
/// swift-crypto-direct `AES128GCMOpener`/`Sealer` and `ChaCha20…Opener`/`Sealer`
/// logic with seam calls. Embedded-clean: no Foundation, no `any`, no swift-crypto,
/// typed throws.
///
/// The cipher suite is selected one level up by ``SuiteProtector`` (a closed enum),
/// which is what replaces the `any PacketOpener`/`any PacketSealer` existentials.

import P2PCoreBytes
import P2PCoreCrypto

public struct PacketProtector<C: CryptoProvider, A: AEAD>: Sendable {
    /// The keyed AEAD instance for this protection key.
    public let aead: A

    /// The 12-byte packet-protection IV (RFC 9001 §5.1, "quic iv").
    public let iv: [UInt8]

    /// The header-protection key (RFC 9001 §5.1, "quic hp"). 16 bytes for AES-GCM,
    /// 32 bytes for ChaCha20-Poly1305. Used with the `HeaderProtectionProvider`
    /// seam to compute the 5-byte mask.
    public let hpKey: [UInt8]

    /// Whether header protection uses the AES (`true`) or ChaCha20 (`false`) mask.
    public let usesAESHeaderProtection: Bool

    /// The required IV length for QUIC AEAD (RFC 9001 §5.3).
    public static var ivLength: Int { 12 }

    /// The AEAD authentication tag length (16 bytes).
    public static var tagLength: Int { A.tagLength }

    /// Creates a protector from a keyed AEAD, IV, and header-protection key.
    ///
    /// - Throws: ``PacketProtectionError/invalidIVLength(expected:actual:)`` if `iv`
    ///   is not 12 bytes.
    public init(
        aead: A,
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

    // MARK: - Nonce (RFC 9001 §5.3)

    /// Constructs the AEAD nonce: `iv XOR left-padded(packet_number)`.
    ///
    /// The packet number is encoded big-endian into the low 8 bytes of the 12-byte
    /// IV and XORed in. Precondition (enforced at init): `iv.count == 12`.
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

    // MARK: - Payload protection (AEAD)

    /// Seals `plaintext` and returns `ciphertext || tag` (RFC 9001 §5.3).
    ///
    /// `header` is the AAD (header up to and including the unprotected packet
    /// number). Routes through the `CryptoProvider.AEAD` seam.
    public func seal(
        _ plaintext: [UInt8],
        packetNumber: UInt64,
        header: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        let nonceBytes = nonce(packetNumber: packetNumber)
        do {
            return try aead.seal(plaintext.span, nonce: nonceBytes.span, aad: header.span)
        } catch {
            throw .crypto(error)
        }
    }

    /// Opens `ciphertext || tag` and returns the plaintext (RFC 9001 §5.3).
    ///
    /// Throws ``PacketProtectionError/crypto(_:)`` wrapping
    /// ``P2PCoreCrypto/CryptoError/authenticationFailure`` on a tag mismatch — no
    /// silent fallback, never a garbage/empty return.
    public func open(
        _ ciphertext: [UInt8],
        packetNumber: UInt64,
        header: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        guard ciphertext.count >= Self.tagLength else {
            throw .ciphertextTooShort(minimum: Self.tagLength, actual: ciphertext.count)
        }
        let nonceBytes = nonce(packetNumber: packetNumber)
        do {
            return try aead.open(ciphertext.span, nonce: nonceBytes.span, aad: header.span)
        } catch {
            throw .crypto(error)
        }
    }

    // MARK: - Header protection (RFC 9001 §5.4)

    /// Computes the 5-byte header-protection mask for `sample` via the
    /// `HeaderProtectionProvider` seam (AES-ECB or ChaCha20 block).
    public func headerProtectionMask(sample: [UInt8]) throws(PacketProtectionError) -> [UInt8] {
        guard sample.count >= 16 else {
            throw .insufficientSample(expected: 16, actual: sample.count)
        }
        do {
            if usesAESHeaderProtection {
                return try C.HeaderProtection.aesECBBlockMask(key: hpKey.span, sample: sample.span)
            } else {
                return try C.HeaderProtection.chaCha20BlockMask(key: hpKey.span, sample: sample.span)
            }
        } catch {
            throw .crypto(error)
        }
    }

    /// Applies header protection to the first byte and packet-number bytes
    /// (RFC 9001 §5.4.1): masks the low 4 bits (long header) or low 5 bits (short
    /// header) of the first byte, and XORs the mask over the packet-number bytes.
    public func applyHeaderProtection(
        sample: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let mask = try headerProtectionMask(sample: sample)
        return Self.applyMask(mask, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
    }

    /// Removes header protection, recovering the unprotected first byte and
    /// packet-number bytes. The XOR mask operation is its own inverse, so this
    /// shares ``applyMask(_:firstByte:packetNumberBytes:)``.
    public func removeHeaderProtection(
        sample: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) throws(PacketProtectionError) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let mask = try headerProtectionMask(sample: sample)
        return Self.applyMask(mask, firstByte: firstByte, packetNumberBytes: packetNumberBytes)
    }

    /// XORs the 5-byte `mask` over the first byte (suite-of-bits depending on header
    /// form) and the packet-number bytes. Self-inverse, used by both apply/remove.
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
        for i in 0..<packetNumberBytes.count {
            maskedPN.append(packetNumberBytes[i] ^ mask[i + 1])
        }
        return (maskedFirstByte, maskedPN)
    }
}
