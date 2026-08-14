import Testing
import QUICWire

@Suite("QUIC wire boundaries")
struct QUICWireTests {
    @Test("QUIC v1 and v2 long-header type mappings remain distinct")
    func versionSpecificLongHeaderTypeMappings() throws {
        #expect(QUICVersion.v1.longPacketType(forTypeBits: 0x00) == .initial)
        #expect(QUICVersion.v1.longPacketType(forTypeBits: 0x03) == .retry)
        #expect(QUICVersion.v2.longPacketType(forTypeBits: 0x00) == .retry)
        #expect(QUICVersion.v2.longPacketType(forTypeBits: 0x01) == .initial)
        #expect(QUICVersion.v2.longPacketType(forTypeBits: 0x02) == .zeroRTT)
        #expect(QUICVersion.v2.longPacketType(forTypeBits: 0x03) == .handshake)

        let cid = try ConnectionID(bytes: [0x01])
        let header = try LongHeader(
            packetType: .initial,
            version: .v2,
            destinationConnectionID: cid,
            sourceConnectionID: cid
        )
        #expect((header.firstByte >> 4) & 0x03 == 0x01)
        #expect(header.packetType == .initial)
    }

    @Test("varints round-trip at every encoding boundary")
    func varintBoundaries() throws {
        let values: [UInt64] = [
            0, 63, 64, 16_383, 16_384,
            1_073_741_823, 1_073_741_824, Varint.maxValue,
        ]
        for value in values {
            let encoded = try Varint(value).encodeBytes()
            let decoded = try Varint.decode(from: encoded)
            #expect(decoded.0.value == value)
            #expect(decoded.1 == encoded.count)
        }
    }

    @Test("truncated varints fail without fallback")
    func truncatedVarintsFail() {
        #expect(throws: Varint.DecodeError.self) {
            _ = try Varint.decode(from: [0x40])
        }
        #expect(throws: Varint.DecodeError.self) {
            _ = try Varint.decode(from: [0xc0, 0, 0, 0])
        }
    }

    @Test("local wire construction rejects invalid values without trapping")
    func invalidLocalConstructionIsTyped() throws {
        #expect(throws: QUICWireError.invalidVarint) {
            _ = try Varint(Varint.maxValue + 1)
        }
        #expect(throws: QUICWireError.invalidVarint) {
            _ = try Varint(Int64(-1))
        }

        let connectionID = try ConnectionID(bytes: [0x01])
        #expect(throws: PacketHeaderConstructionError.invalidLongHeaderPacketType(.oneRTT)) {
            _ = try LongHeader(
                packetType: .oneRTT,
                version: .v1,
                destinationConnectionID: connectionID,
                sourceConnectionID: connectionID
            )
        }
        #expect(throws: PacketHeaderConstructionError.invalidPacketNumberLength(0)) {
            _ = try ShortHeader(
                destinationConnectionID: connectionID,
                packetNumberLength: 0
            )
        }
        #expect(throws: ConnectionID.ConnectionIDError.tooLong(length: 21, maxAllowed: 20)) {
            _ = try ConnectionID(bytes: [UInt8](repeating: 0, count: 21))
        }
    }

    @Test("frame codec round-trips stream and ACK payloads")
    func frameRoundTrip() throws {
        let codec = StandardFrameCodec()
        let frames: [Frame] = [
            .stream(StreamFrame(
                streamID: 4,
                offset: 1000,
                data: [0xaa, 0xbb, 0xcc],
                fin: true
            )),
            .ack(AckFrame(
                largestAcknowledged: 100,
                ackDelay: 25,
                ackRanges: [AckRange(gap: 0, rangeLength: 10)]
            )),
        ]
        let encoded = try codec.encodeFrames(frames)
        #expect(try codec.decodeFrames(from: encoded) == frames)
    }

    @Test("frame decoder rejects incomplete frame types")
    func incompleteFrameTypeFails() {
        let codec = StandardFrameCodec()
        #expect(throws: FrameCodecError.self) {
            _ = try codec.decodeFrames(from: [0xff])
        }
    }

    @Test("ACK codec rejects packet-number underflow instead of clamping")
    func ackRangeUnderflowFails() {
        let codec = StandardFrameCodec()
        #expect(throws: FrameCodecError.self) {
            _ = try codec.decodeFrames(from: [0x02, 0, 0, 0, 1])
        }
        #expect(throws: FrameCodecError.self) {
            _ = try codec.decodeFrames(from: [0x02, 1, 0, 1, 0, 0, 0])
        }
        #expect(throws: FrameCodecError.self) {
            _ = try codec.encodeBytes(.ack(AckFrame(
                largestAcknowledged: 0,
                ackDelay: 0,
                ackRanges: [AckRange(gap: 0, rangeLength: 1)]
            )))
        }
    }

    @Test("stream-count frames reject values above 2^60")
    func streamCountLimit() throws {
        let codec = StandardFrameCodec()
        let invalidCount = ProtocolLimits.maxStreams + 1
        var writer = QUICWireWriter()
        writer.writeByte(0x12)
        try writer.writeVarint(invalidCount)

        #expect(throws: FrameCodecError.self) {
            _ = try codec.decodeFrames(from: writer.finishArray())
        }
        #expect(throws: FrameCodecError.self) {
            _ = try codec.encodeBytes(.maxStreams(MaxStreamsFrame(
                maxStreams: invalidCount,
                isBidirectional: true
            )))
        }
        #expect(throws: FrameCodecError.self) {
            _ = try codec.encodeBytes(.streamsBlocked(StreamsBlockedFrame(
                streamLimit: invalidCount,
                isBidirectional: false
            )))
        }
    }

    @Test("NEW_CONNECTION_ID rejects retirement beyond its sequence")
    func invalidConnectionIDRetirement() {
        let codec = StandardFrameCodec()
        var bytes: [UInt8] = [0x18, 0, 1, 1, 0xAA]
        bytes.append(contentsOf: [UInt8](repeating: 0, count: 16))
        #expect(throws: FrameCodecError.self) {
            _ = try codec.decodeFrames(from: bytes)
        }
    }
}
