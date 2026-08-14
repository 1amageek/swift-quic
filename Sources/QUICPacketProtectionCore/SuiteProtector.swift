import NetworkingCore
import SSLCrypto

/// The packet-protection cipher suite (RFC 9001 §5.3 / TLS 1.3 §B.4).
public enum QUICProtectionSuite: Sendable, Equatable {
    case aes128GCM
    case aes256GCM
    case chaCha20Poly1305

    public var keyLength: Int {
        switch self {
        case .aes128GCM: return 16
        case .aes256GCM, .chaCha20Poly1305: return 32
        }
    }

    public var usesAESHeaderProtection: Bool {
        switch self {
        case .aes128GCM, .aes256GCM: return true
        case .chaCha20Poly1305: return false
        }
    }
}

/// Immutable owner and closed dispatcher for one QUIC packet-protection suite.
///
/// Cipher selection is private so callers cannot couple themselves to concrete
/// key-schedule ownership. The noncopyable cipher remains in one non-generic
/// owner while `SuiteProtector` itself has reference semantics for engine slots.
public final class SuiteProtector: Sendable {
    private enum Cipher: ~Copyable, Sendable {
        case aesGCM(AESGCM)
        case chaCha20Poly1305(ChaCha20Poly1305)
    }

    public let suite: QUICProtectionSuite
    private let cipher: Cipher
    private let iv: [UInt8]
    private let hpKey: [UInt8]

    private init(
        suite: QUICProtectionSuite,
        cipher: consuming Cipher,
        iv: [UInt8],
        hpKey: [UInt8]
    ) throws(PacketProtectionError) {
        guard iv.count == 12 else {
            throw .invalidIVLength(expected: 12, actual: iv.count)
        }
        self.suite = suite
        self.cipher = cipher
        self.iv = iv
        self.hpKey = hpKey
    }

    public static func make(
        suite: QUICProtectionSuite,
        key: [UInt8],
        iv: [UInt8],
        hpKey: [UInt8]
    ) throws(PacketProtectionError) -> SuiteProtector {
        guard key.count == suite.keyLength else {
            throw .invalidKeyLength(expected: suite.keyLength, actual: key.count)
        }
        guard hpKey.count == suite.keyLength else {
            throw .invalidHeaderProtectionKeyLength(expected: suite.keyLength, actual: hpKey.count)
        }
        switch suite {
        case .aes128GCM:
            let aead: AESGCM
            do { aead = try AESGCM(key: key.span) } catch let error { throw .aead(error) }
            return try SuiteProtector(
                suite: suite,
                cipher: .aesGCM(aead),
                iv: iv,
                hpKey: hpKey
            )
        case .aes256GCM:
            let aead: AESGCM
            do { aead = try AESGCM(key: key.span) } catch let error { throw .aead(error) }
            return try SuiteProtector(
                suite: suite,
                cipher: .aesGCM(aead),
                iv: iv,
                hpKey: hpKey
            )
        case .chaCha20Poly1305:
            let aead: ChaCha20Poly1305
            do { aead = try ChaCha20Poly1305(key: key.span) } catch let error { throw .aead(error) }
            return try SuiteProtector(
                suite: suite,
                cipher: .chaCha20Poly1305(aead),
                iv: iv,
                hpKey: hpKey
            )
        }
    }

    public func seal(
        _ plaintext: Span<UInt8>,
        packetNumber: UInt64,
        header: Span<UInt8>
    ) throws(PacketProtectionError) -> [UInt8] {
        let nonceBytes = nonce(packetNumber: packetNumber)
        var output = [UInt8](repeating: 0, count: plaintext.count + 16)
        do {
            var destination = output.mutableSpan
            switch cipher {
            case .aesGCM(let aead):
                try aead.seal(
                    plaintext: plaintext,
                    authenticatedData: header,
                    nonce: nonceBytes.span,
                    into: &destination
                )
            case .chaCha20Poly1305(let aead):
                try aead.seal(
                    plaintext: plaintext,
                    authenticatedData: header,
                    nonce: nonceBytes.span,
                    into: &destination
                )
            }
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
        guard ciphertext.count >= 16 else {
            throw .ciphertextTooShort(minimum: 16, actual: ciphertext.count)
        }
        let nonceBytes = nonce(packetNumber: packetNumber)
        var output = [UInt8](repeating: 0, count: ciphertext.count - 16)
        do {
            var destination = output.mutableSpan
            switch cipher {
            case .aesGCM(let aead):
                try aead.open(
                    ciphertextAndTag: ciphertext,
                    authenticatedData: header,
                    nonce: nonceBytes.span,
                    into: &destination
                )
            case .chaCha20Poly1305(let aead):
                try aead.open(
                    ciphertextAndTag: ciphertext,
                    authenticatedData: header,
                    nonce: nonceBytes.span,
                    into: &destination
                )
            }
            return output
        } catch let error {
            throw .aead(error)
        }
    }

    public func headerProtectionMask(sample: Span<UInt8>) throws(PacketProtectionError) -> [UInt8] {
        guard sample.count >= 16 else {
            throw .insufficientSample(expected: 16, actual: sample.count)
        }
        let key = hpKey
        let exactSample = sample.extracting(0..<16)
        do throws(AEADError) {
            let mask: ContiguousArray<UInt8>
            if suite.usesAESHeaderProtection {
                mask = try QUICHeaderProtection.aes(key: key.span, sample: exactSample)
            } else {
                mask = try QUICHeaderProtection.chaCha20(key: key.span, sample: exactSample)
            }
            return Array(mask)
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

    private func nonce(packetNumber: UInt64) -> [UInt8] {
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

    private static func applyMask(
        _ mask: [UInt8],
        firstByte: UInt8,
        packetNumberBytes: [UInt8]
    ) -> (firstByte: UInt8, packetNumberBytes: [UInt8]) {
        let isLongHeader = (firstByte & 0x80) != 0
        let firstByteMask: UInt8 = isLongHeader ? 0x0F : 0x1F
        let maskedFirstByte = firstByte ^ (mask[0] & firstByteMask)
        var maskedPacketNumber = [UInt8]()
        maskedPacketNumber.reserveCapacity(packetNumberBytes.count)
        for index in packetNumberBytes.indices {
            maskedPacketNumber.append(packetNumberBytes[index] ^ mask[index + 1])
        }
        return (maskedFirstByte, maskedPacketNumber)
    }
}
