/// QUIC Packet Codec Tests
///
/// Tests for PacketEncoder and PacketDecoder implementations.

import Testing
import Foundation
@testable import QUICCore

// MARK: - Mock Sealer/Opener

/// Mock sealer for testing that performs simple XOR encryption
struct MockPacketSealer: PacketSealerProtocol {
    let key: UInt8

    func applyHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        // Simple XOR with first byte of sample
        // Use sample.first to handle Data slices with non-zero startIndex
        let mask = sample[sample.startIndex]
        let protectedFirstByte = firstByte ^ (mask & 0x0F)  // Mask lower 4 bits for long header
        let protectedPN = Data(packetNumberBytes.map { $0 ^ mask })
        return (protectedFirstByte, protectedPN)
    }

    func seal(
        plaintext: Data,
        packetNumber: UInt64,
        header: Data
    ) throws -> Data {
        // Simple XOR encryption for testing
        var ciphertext = Data(plaintext.map { $0 ^ key })
        // Append mock AEAD tag (16 bytes)
        ciphertext.append(Data(repeating: key, count: 16))
        return ciphertext
    }
}

/// Mock opener for testing that performs simple XOR decryption
struct MockPacketOpener: PacketOpenerProtocol {
    let key: UInt8

    func removeHeaderProtection(
        sample: Data,
        firstByte: UInt8,
        packetNumberBytes: Data
    ) throws -> (UInt8, Data) {
        // Simple XOR with first byte of sample (same as apply, XOR is symmetric)
        // Use sample.startIndex to handle Data slices with non-zero startIndex
        let mask = sample[sample.startIndex]
        let unprotectedFirstByte = firstByte ^ (mask & 0x0F)
        let unprotectedPN = Data(packetNumberBytes.map { $0 ^ mask })
        return (unprotectedFirstByte, unprotectedPN)
    }

    func open(
        ciphertext: Data,
        packetNumber: UInt64,
        header: Data
    ) throws -> Data {
        // Remove mock AEAD tag (16 bytes) and XOR decrypt
        guard ciphertext.count >= 16 else {
            throw PacketCodecError.decryptionFailed
        }
        let encryptedPayload = ciphertext.dropLast(16)
        return Data(encryptedPayload.map { $0 ^ key })
    }
}

// MARK: - Packet Encoder Tests

@Suite("Packet Encoder Tests")
struct PacketEncoderTests {

    @Test("Encode Initial packet with frames")
    func encodeInitialPacket() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0xAB)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let scid = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: Data(),  // Empty token for Initial
            packetNumberLength: 2
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02, 0x03]))),
            .padding(count: 10)
        ]

        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        // Verify packet was created
        #expect(encoded.count > 0)

        // First byte should have form bit set (long header)
        #expect((encoded[0] & 0x80) == 0x80)

        // Version should be present at bytes 1-4
        let version = UInt32(encoded[1]) << 24 |
                      UInt32(encoded[2]) << 16 |
                      UInt32(encoded[3]) << 8 |
                      UInt32(encoded[4])
        #expect(version == QUICVersion.v1.rawValue)
    }

    @Test("Encode Handshake packet")
    func encodeHandshakePacket() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0xCD)

        let dcid = try ConnectionID(bytes: Data([0x11, 0x22, 0x33, 0x44]))
        let scid = try ConnectionID(bytes: Data([0x55, 0x66, 0x77, 0x88]))

        let header = LongHeader(
            packetType: .handshake,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumberLength: 2
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data([0xAA, 0xBB, 0xCC]))),
        ]

        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 1,
            sealer: sealer
        )

        #expect(encoded.count > 0)

        // First byte: long header + handshake type
        #expect((encoded[0] & 0x80) == 0x80)
    }

    @Test("Encode 1-RTT packet (short header)")
    func encodeShortHeaderPacket() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0xEF)

        let dcid = try ConnectionID(bytes: Data([0xDE, 0xAD, 0xBE, 0xEF]))

        let header = ShortHeader(
            destinationConnectionID: dcid,
            packetNumberLength: 2,
            spinBit: false,
            keyPhase: false
        )

        let frames: [Frame] = [
            .stream(StreamFrame(streamID: 4, offset: 0, data: Data([0x01, 0x02, 0x03, 0x04, 0x05]), fin: false)),
        ]

        let encoded = try encoder.encodeShortHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 100,
            sealer: sealer
        )

        #expect(encoded.count > 0)

        // First byte should NOT have form bit set (short header)
        #expect((encoded[0] & 0x80) == 0x00)
    }

    @Test("Encode packet with multiple frames")
    func encodeMultipleFrames() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0x42)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02]))
        let scid = try ConnectionID(bytes: Data([0x03, 0x04]))

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: Data(),
            packetNumberLength: 1
        )

        let frames: [Frame] = [
            .ping,
            .crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02]))),
            .ack(AckFrame(largestAcknowledged: 5, ackDelay: 10, ackRanges: [])),
            .padding(count: 5)
        ]

        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        #expect(encoded.count > 0)
    }

    @Test("Packet number encoding with different lengths")
    func packetNumberEncoding() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0x00)

        let dcid = try ConnectionID(bytes: Data([0x01]))
        let scid = try ConnectionID(bytes: Data([0x02]))

        // Test with 4-byte packet number
        let header = LongHeader(
            packetType: .handshake,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumberLength: 4
        )

        let frames: [Frame] = [.ping]

        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0x12345678,
            sealer: sealer
        )

        #expect(encoded.count > 0)
    }
}

// MARK: - Packet Decoder Tests

@Suite("Packet Decoder Tests")
struct PacketDecoderTests {

    @Test("Decode long header packet type")
    func decodeLongHeaderType() throws {
        // Test header parsing using the static method
        var packet = Data()

        // First byte: 1100 0000 (long header, Initial type, 2-byte PN)
        packet.append(0xC0 | 0x01)  // PN length = 2

        // Version
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // Version 1

        // DCID length + DCID
        packet.append(4)
        packet.append(contentsOf: [0x01, 0x02, 0x03, 0x04])

        // SCID length + SCID
        packet.append(4)
        packet.append(contentsOf: [0x05, 0x06, 0x07, 0x08])

        // Token length (varint) + no token
        packet.append(0x00)

        // Length (varint) - include PN + payload + tag
        packet.append(0x18)  // 24 bytes

        // Packet number (2 bytes, protected - just dummy for parsing)
        packet.append(contentsOf: [0x00, 0x01])

        // Encrypted payload (need at least 20 bytes for sample + some payload)
        packet.append(contentsOf: Data(repeating: 0xAB, count: 22))

        // Parse header only (not full decryption)
        let (header, _) = try PacketHeader.parse(from: packet, dcidLength: 4)

        if case .long(let longHeader) = header {
            #expect(longHeader.packetType == .initial)
            #expect(longHeader.version == .v1)
            #expect(longHeader.destinationConnectionID.bytes == Data([0x01, 0x02, 0x03, 0x04]))
            #expect(longHeader.sourceConnectionID.bytes == Data([0x05, 0x06, 0x07, 0x08]))
        } else {
            Issue.record("Expected long header")
        }
    }

    @Test("Decode Version Negotiation packet")
    func decodeVersionNegotiation() throws {
        let decoder = PacketDecoder()

        var packet = Data()

        // First byte: long header form, random bits
        packet.append(0x80)

        // Version: 0 (Version Negotiation)
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x00])

        // DCID length + DCID
        packet.append(4)
        packet.append(contentsOf: [0x01, 0x02, 0x03, 0x04])

        // SCID length + SCID
        packet.append(4)
        packet.append(contentsOf: [0x05, 0x06, 0x07, 0x08])

        // Supported versions
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x01])  // Version 1
        packet.append(contentsOf: [0x6B, 0x33, 0x43, 0xCF])  // Version 2

        let parsed = try decoder.decodePacket(data: packet, dcidLength: 4, opener: nil)

        if case .long(let longHeader) = parsed.header {
            #expect(longHeader.packetType == .versionNegotiation)
            #expect(longHeader.version.rawValue == 0)
        } else {
            Issue.record("Expected long header")
        }
    }

    @Test("Decode short header packet type")
    func decodeShortHeaderType() throws {
        var packet = Data()

        // First byte: 0100 0001 (short header, fixed bit, 2-byte PN)
        packet.append(0x40 | 0x01)

        // DCID (using dcidLength parameter)
        packet.append(contentsOf: [0xDE, 0xAD, 0xBE, 0xEF])

        // Packet number (2 bytes, protected)
        packet.append(contentsOf: [0x00, 0x01])

        // Encrypted payload
        packet.append(contentsOf: Data(repeating: 0xCD, count: 20))

        // Parse header only (not full decryption)
        let (header, _) = try PacketHeader.parse(from: packet, dcidLength: 4)

        if case .short(let shortHeader) = header {
            #expect(shortHeader.destinationConnectionID.bytes == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        } else {
            Issue.record("Expected short header")
        }
    }

    @Test("Decode Retry packet")
    func decodeRetryPacket() throws {
        let decoder = PacketDecoder()

        var packet = Data()

        // First byte: long header form + Retry type (0xF0)
        packet.append(0xF0)

        // Version
        packet.append(contentsOf: [0x00, 0x00, 0x00, 0x01])

        // DCID length + DCID
        packet.append(4)
        packet.append(contentsOf: [0x01, 0x02, 0x03, 0x04])

        // SCID length + SCID
        packet.append(4)
        packet.append(contentsOf: [0x05, 0x06, 0x07, 0x08])

        // Retry token (variable)
        packet.append(contentsOf: [0xAA, 0xBB, 0xCC, 0xDD])

        // Retry integrity tag (16 bytes)
        packet.append(contentsOf: Data(repeating: 0x00, count: 16))

        let parsed = try decoder.decodePacket(data: packet, dcidLength: 4, opener: nil)

        if case .long(let longHeader) = parsed.header {
            #expect(longHeader.packetType == .retry)
        } else {
            Issue.record("Expected long header")
        }
    }
}

// MARK: - Roundtrip Tests

@Suite("Packet Roundtrip Tests")
struct PacketRoundtripTests {

    @Test("Roundtrip Initial packet")
    func roundtripInitialPacket() throws {
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()
        let key: UInt8 = 0x42
        let sealer = MockPacketSealer(key: key)
        let opener = MockPacketOpener(key: key)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let scid = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: Data(),
            packetNumberLength: 2
        )

        let originalFrames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02, 0x03, 0x04, 0x05]))),
        ]

        let packetNumber: UInt64 = 0

        // Encode (padToMinimum: false to test exact roundtrip without RFC padding)
        let encoded = try encoder.encodeLongHeaderPacket(
            frames: originalFrames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer,
            padToMinimum: false
        )

        // Decode
        let decoded = try decoder.decodePacket(
            data: encoded,
            dcidLength: 4,
            opener: opener
        )

        // Verify header
        if case .long(let decodedHeader) = decoded.header {
            #expect(decodedHeader.packetType == .initial)
            #expect(decodedHeader.version == .v1)
            #expect(decodedHeader.destinationConnectionID == dcid)
            #expect(decodedHeader.sourceConnectionID == scid)
        } else {
            Issue.record("Expected long header")
        }

        // Verify frames
        #expect(decoded.frames.count == originalFrames.count)
        if case .crypto(let cryptoFrame) = decoded.frames[0] {
            #expect(cryptoFrame.offset == 0)
            #expect(cryptoFrame.data == Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        } else {
            Issue.record("Expected CRYPTO frame")
        }
    }

    @Test("Initial packet is padded to 1200 bytes by default")
    func initialPacketPadding() throws {
        let encoder = PacketEncoder()
        let key: UInt8 = 0x42
        let sealer = MockPacketSealer(key: key)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
        let scid = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: Data(),
            packetNumberLength: 2
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02, 0x03]))),
        ]

        // Encode with default padding (padToMinimum: true)
        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        // RFC 9000 Section 14.1: Initial packets MUST be at least 1200 bytes
        #expect(encoded.count >= PacketEncoder.initialPacketMinSize)
    }

    @Test("Roundtrip Handshake packet")
    func roundtripHandshakePacket() throws {
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()
        let key: UInt8 = 0x88
        let sealer = MockPacketSealer(key: key)
        let opener = MockPacketOpener(key: key)

        let dcid = try ConnectionID(bytes: Data([0xAA, 0xBB]))
        let scid = try ConnectionID(bytes: Data([0xCC, 0xDD]))

        let header = LongHeader(
            packetType: .handshake,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumberLength: 1
        )

        let originalFrames: [Frame] = [
            .ack(AckFrame(largestAcknowledged: 10, ackDelay: 5, ackRanges: [])),
            .crypto(CryptoFrame(offset: 100, data: Data([0xDE, 0xAD, 0xBE, 0xEF]))),
        ]

        let packetNumber: UInt64 = 5

        // Encode
        let encoded = try encoder.encodeLongHeaderPacket(
            frames: originalFrames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer
        )

        // Decode
        let decoded = try decoder.decodePacket(
            data: encoded,
            dcidLength: 2,
            opener: opener
        )

        // Verify header
        if case .long(let decodedHeader) = decoded.header {
            #expect(decodedHeader.packetType == .handshake)
            #expect(decodedHeader.destinationConnectionID == dcid)
            #expect(decodedHeader.sourceConnectionID == scid)
        } else {
            Issue.record("Expected long header")
        }

        // Verify frames
        #expect(decoded.frames.count == 2)
    }

    @Test("Roundtrip 1-RTT packet")
    func roundtripShortHeaderPacket() throws {
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()
        let key: UInt8 = 0xFF
        let sealer = MockPacketSealer(key: key)
        let opener = MockPacketOpener(key: key)

        let dcid = try ConnectionID(bytes: Data([0x12, 0x34, 0x56, 0x78]))

        let header = ShortHeader(
            destinationConnectionID: dcid,
            packetNumberLength: 2,
            spinBit: true,
            keyPhase: false
        )

        let originalFrames: [Frame] = [
            .stream(StreamFrame(streamID: 0, offset: 0, data: Data([0x01, 0x02, 0x03, 0x04, 0x05]), fin: false)),
            .ping,
        ]

        let packetNumber: UInt64 = 1000

        // Encode
        let encoded = try encoder.encodeShortHeaderPacket(
            frames: originalFrames,
            header: header,
            packetNumber: packetNumber,
            sealer: sealer
        )

        // Decode
        let decoded = try decoder.decodePacket(
            data: encoded,
            dcidLength: 4,
            opener: opener
        )

        // Verify header
        if case .short(let decodedHeader) = decoded.header {
            #expect(decodedHeader.destinationConnectionID == dcid)
        } else {
            Issue.record("Expected short header")
        }

        // Verify frames
        #expect(decoded.frames.count == 2)
        if case .stream(let streamFrame) = decoded.frames[0] {
            #expect(streamFrame.streamID == 0)
            #expect(streamFrame.data == Data([0x01, 0x02, 0x03, 0x04, 0x05]))
        } else {
            Issue.record("Expected STREAM frame")
        }
    }
}

// MARK: - Header Protection Tests (RFC 9001 Section 5.4.1)

@Suite("Header Protection Tests")
struct HeaderProtectionTests {

    @Test("Header protection reads 4 PN bytes before unmasking")
    func headerProtectionReads4Bytes() throws {
        // This test verifies that the decoder ALWAYS reads 4 PN bytes
        // before removing header protection, as required by RFC 9001 Section 5.4.1
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()

        // Use different PN lengths to verify correct handling
        for pnLength in 1...4 {
            let key: UInt8 = UInt8(pnLength * 0x11)
            let sealer = MockPacketSealer(key: key)
            let opener = MockPacketOpener(key: key)

            let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))
            let scid = try ConnectionID(bytes: Data([0x05, 0x06, 0x07, 0x08]))

            let header = LongHeader(
                packetType: .initial,
                version: .v1,
                destinationConnectionID: dcid,
                sourceConnectionID: scid,
                token: Data(),
                packetNumberLength: pnLength
            )

            let frames: [Frame] = [
                .crypto(CryptoFrame(offset: 0, data: Data([0x01, 0x02, 0x03]))),
            ]

            let packetNumber: UInt64 = UInt64(1 << ((pnLength - 1) * 8))

            // Encode
            let encoded = try encoder.encodeLongHeaderPacket(
                frames: frames,
                header: header,
                packetNumber: packetNumber,
                sealer: sealer
            )

            // Decode - should succeed for all PN lengths
            let decoded = try decoder.decodePacket(
                data: encoded,
                dcidLength: 4,
                opener: opener
            )

            // Verify the packet number was correctly decoded
            #expect(decoded.packetNumber == packetNumber, "PN length \(pnLength) failed")

            // Verify header
            if case .long(let longHeader) = decoded.header {
                #expect(longHeader.packetNumberLength == pnLength)
            } else {
                Issue.record("Expected long header for PN length \(pnLength)")
            }
        }
    }

    @Test("Short header packet number decoding with various lengths")
    func shortHeaderPNDecoding() throws {
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()

        for pnLength in 1...4 {
            let key: UInt8 = UInt8(pnLength * 0x22)
            let sealer = MockPacketSealer(key: key)
            let opener = MockPacketOpener(key: key)

            let dcid = try ConnectionID(bytes: Data([0xAA, 0xBB, 0xCC, 0xDD]))

            let header = ShortHeader(
                destinationConnectionID: dcid,
                packetNumberLength: pnLength,
                spinBit: false,
                keyPhase: false
            )

            let frames: [Frame] = [
                .stream(StreamFrame(streamID: 0, offset: 0, data: Data([0x01, 0x02, 0x03, 0x04, 0x05]), fin: false)),
            ]

            let packetNumber: UInt64 = UInt64(1 << ((pnLength - 1) * 8)) + 100

            // Encode
            let encoded = try encoder.encodeShortHeaderPacket(
                frames: frames,
                header: header,
                packetNumber: packetNumber,
                sealer: sealer
            )

            // Decode
            let decoded = try decoder.decodePacket(
                data: encoded,
                dcidLength: 4,
                opener: opener
            )

            // Verify
            #expect(decoded.packetNumber == packetNumber, "Short header PN length \(pnLength) failed")
        }
    }

    @Test("Long header packet uses Length field for boundary")
    func longHeaderUsesLengthField() throws {
        let encoder = PacketEncoder()
        let decoder = PacketDecoder()
        let key: UInt8 = 0x55
        let sealer = MockPacketSealer(key: key)
        let opener = MockPacketOpener(key: key)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02]))
        let scid = try ConnectionID(bytes: Data([0x03, 0x04]))

        let header = LongHeader(
            packetType: .handshake,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            packetNumberLength: 2
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data([0xAA, 0xBB, 0xCC]))),
        ]

        // Encode
        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 42,
            sealer: sealer
        )

        // Add trailing garbage (simulating coalesced packet scenario)
        var withTrailing = encoded
        withTrailing.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])

        // Decode - should only decode the first packet using Length field
        let decoded = try decoder.decodePacket(
            data: withTrailing,
            dcidLength: 2,
            opener: opener
        )

        // Verify the packet was decoded correctly
        #expect(decoded.packetNumber == 42)

        // The packetSize should match the original encoded size (not including trailing bytes)
        #expect(decoded.packetSize == encoded.count)
    }
}

// MARK: - Utility Tests

@Suite("Packet Codec Utility Tests")
struct PacketCodecUtilityTests {

    @Test("Packet size is within MTU")
    func packetSizeWithinMTU() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0x00)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))

        let header = ShortHeader(
            destinationConnectionID: dcid,
            packetNumberLength: 2,
            spinBit: false,
            keyPhase: false
        )

        // Need enough payload for header protection sample (at least 4 bytes after PN + 16 sample)
        // Use padding to ensure sufficient size
        let frames: [Frame] = [
            .ping,
            .padding(count: 5)  // Add padding to ensure sample has enough data
        ]

        let encoded = try encoder.encodeShortHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        // Verify the encoded packet size is within MTU
        #expect(encoded.count <= PacketEncoder.defaultMTU)
    }

    @Test("Short header packet has correct structure")
    func shortHeaderPacketStructure() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0x00)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02, 0x03, 0x04]))

        let header = ShortHeader(
            destinationConnectionID: dcid,
            packetNumberLength: 2,
            spinBit: false,
            keyPhase: false
        )

        // Need enough payload for header protection sample
        let frames: [Frame] = [
            .ping,
            .padding(count: 5)
        ]

        let encoded = try encoder.encodeShortHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        // Minimum size: 1 (first byte) + 4 (DCID) + 2 (PN) + 6 (frames) + 16 (tag) = 29
        #expect(encoded.count >= 29)

        // First byte should be short header (form bit = 0, fixed bit = 1)
        #expect((encoded[0] & 0x80) == 0x00)  // Form bit = 0
        #expect((encoded[0] & 0x40) == 0x40)  // Fixed bit = 1
    }

    @Test("Long header packet has correct structure")
    func longHeaderPacketStructure() throws {
        let encoder = PacketEncoder()
        let sealer = MockPacketSealer(key: 0x00)

        let dcid = try ConnectionID(bytes: Data([0x01, 0x02]))
        let scid = try ConnectionID(bytes: Data([0x03, 0x04]))

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: Data(),
            packetNumberLength: 1
        )

        // Need enough payload for header protection sample
        let frames: [Frame] = [.ping, .padding(count: 5)]

        let encoded = try encoder.encodeLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0,
            sealer: sealer
        )

        // First byte should be long header (form bit = 1, fixed bit = 1)
        #expect((encoded[0] & 0x80) == 0x80)  // Form bit = 1
        #expect((encoded[0] & 0x40) == 0x40)  // Fixed bit = 1
    }
}
