/// QUIC Frame Encoding and Decoding (RFC 9000 Section 12)
///
/// Provides encoding and decoding for all QUIC frame types.
///
/// Embedded-clean: no Foundation, no `any`. Encoding flows through
/// `P2PCoreBytes` `ByteWriter`; decoding through `ByteReader`; byte payloads are
/// `[UInt8]`; all failures are typed (``FrameCodecError``). The Foundation
/// adapter restores the historical `Data`-based / `DataReader`-based surface
/// (`encode(_:) -> Data`, `decode(from: inout DataReader)`,
/// `decodeFrames(from: Data)`).

import P2PCoreBytes

// MARK: - Frame Codec Errors

/// Errors that can occur during frame encoding/decoding
public enum FrameCodecError: Error, Sendable {
    /// Insufficient data to decode frame
    case insufficientData
    /// Unknown or invalid frame type
    case unknownFrameType(UInt64)
    /// Invalid frame format
    case invalidFrameFormat(String)
    /// Frame too large
    case frameTooLarge(Int)
}

// MARK: - Frame Encoder Protocol

/// Protocol for encoding frames to binary data
public protocol FrameEncoder: Sendable {
    /// Encodes a single frame to a byte array
    /// - Parameter frame: The frame to encode
    /// - Returns: The encoded frame bytes
    func encodeBytes(_ frame: Frame) throws(FrameCodecError) -> [UInt8]

    /// Encodes multiple frames to a byte array
    /// - Parameter frames: The frames to encode
    /// - Returns: The concatenated encoded frame bytes
    func encodeFrames(_ frames: [Frame]) throws(FrameCodecError) -> [UInt8]
}

// MARK: - Frame Decoder Protocol

/// Protocol for decoding frames from binary data
public protocol FrameDecoder: Sendable {
    /// Decodes a single frame from a byte reader
    /// - Parameter reader: The reader positioned at the frame start
    /// - Returns: The decoded frame
    func decode(from reader: inout ByteReader) throws(FrameCodecError) -> Frame

    /// Decodes all frames from a byte array
    /// - Parameter bytes: The bytes containing one or more frames
    /// - Returns: Array of decoded frames
    func decodeFrames(from bytes: [UInt8]) throws(FrameCodecError) -> [Frame]
}

// MARK: - Standard Frame Codec

/// Standard implementation of frame encoding and decoding.
///
/// The single concrete `FrameEncoder`/`FrameDecoder`. Encoding pre-computes the
/// exact frame size (via ``FrameSize``) and reserves capacity to avoid
/// reallocations; decoding uses a single-byte varint fast path for the common
/// frame types (0x00-0x3F).
public struct StandardFrameCodec: FrameEncoder, FrameDecoder, Sendable {

    public init() {}

    // MARK: - Encoding

    /// Encodes a frame to a byte array.
    public func encodeBytes(_ frame: Frame) throws(FrameCodecError) -> [UInt8] {
        // Pre-calculate frame size and reserve exact capacity to avoid reallocations.
        let frameSize = FrameSize.frame(frame)
        var writer = ByteWriter(reservingCapacity: frameSize)
        try encodeFrame(frame, to: &writer)
        return writer.finishArray()
    }

    /// Encodes multiple frames to a byte array.
    public func encodeFrames(_ frames: [Frame]) throws(FrameCodecError) -> [UInt8] {
        // Pre-calculate total size for all frames to avoid reallocations.
        var totalSize = 0
        for frame in frames {
            totalSize += FrameSize.frame(frame)
        }
        var writer = ByteWriter(reservingCapacity: totalSize)
        for frame in frames {
            try encodeFrame(frame, to: &writer)
        }
        return writer.finishArray()
    }

    /// Internal encode implementation.
    internal func encodeFrame(_ frame: Frame, to writer: inout ByteWriter) throws(FrameCodecError) {
        switch frame {
        case .padding(let count):
            // PADDING frames are just 0x00 bytes.
            writer.qWriteZeroBytes(count)

        case .ping:
            // PING frame: just type byte.
            writer.writeByte(0x01)

        case .ack(let ackFrame):
            try encodeAckFrame(ackFrame, to: &writer)

        case .resetStream(let resetFrame):
            writer.writeByte(0x04)
            try writeVarint(resetFrame.streamID, to: &writer)
            try writeVarint(resetFrame.applicationErrorCode, to: &writer)
            try writeVarint(resetFrame.finalSize, to: &writer)

        case .stopSending(let stopFrame):
            writer.writeByte(0x05)
            try writeVarint(stopFrame.streamID, to: &writer)
            try writeVarint(stopFrame.applicationErrorCode, to: &writer)

        case .crypto(let cryptoFrame):
            writer.writeByte(0x06)
            try writeVarint(cryptoFrame.offset, to: &writer)
            try writeVarint(UInt64(cryptoFrame.data.count), to: &writer)
            writer.writeBytes(cryptoFrame.data)

        case .newToken(let token):
            writer.writeByte(0x07)
            try writeVarint(UInt64(token.count), to: &writer)
            writer.writeBytes(token)

        case .stream(let streamFrame):
            try encodeStreamFrame(streamFrame, to: &writer)

        case .maxData(let maxData):
            writer.writeByte(0x10)
            try writeVarint(maxData, to: &writer)

        case .maxStreamData(let maxStreamData):
            writer.writeByte(0x11)
            try writeVarint(maxStreamData.streamID, to: &writer)
            try writeVarint(maxStreamData.maxStreamData, to: &writer)

        case .maxStreams(let maxStreams):
            writer.writeByte(maxStreams.isBidirectional ? 0x12 : 0x13)
            try writeVarint(maxStreams.maxStreams, to: &writer)

        case .dataBlocked(let limit):
            writer.writeByte(0x14)
            try writeVarint(limit, to: &writer)

        case .streamDataBlocked(let blocked):
            writer.writeByte(0x15)
            try writeVarint(blocked.streamID, to: &writer)
            try writeVarint(blocked.streamDataLimit, to: &writer)

        case .streamsBlocked(let blocked):
            writer.writeByte(blocked.isBidirectional ? 0x16 : 0x17)
            try writeVarint(blocked.streamLimit, to: &writer)

        case .newConnectionID(let newCID):
            writer.writeByte(0x18)
            try writeVarint(newCID.sequenceNumber, to: &writer)
            try writeVarint(newCID.retirePriorTo, to: &writer)
            writer.writeByte(UInt8(newCID.connectionID.length))
            writer.writeBytes(newCID.connectionID.bytes)
            writer.writeBytes(newCID.statelessResetToken)

        case .retireConnectionID(let sequenceNumber):
            writer.writeByte(0x19)
            try writeVarint(sequenceNumber, to: &writer)

        case .pathChallenge(let data):
            // RFC 9000 Section 19.17: PATH_CHALLENGE carries exactly 8 bytes
            guard data.count == 8 else {
                throw FrameCodecError.invalidFrameFormat(
                    "PATH_CHALLENGE data must be exactly 8 bytes, got \(data.count)"
                )
            }
            writer.writeByte(0x1a)
            writer.writeBytes(data)

        case .pathResponse(let data):
            // RFC 9000 Section 19.18: PATH_RESPONSE carries exactly 8 bytes
            guard data.count == 8 else {
                throw FrameCodecError.invalidFrameFormat(
                    "PATH_RESPONSE data must be exactly 8 bytes, got \(data.count)"
                )
            }
            writer.writeByte(0x1b)
            writer.writeBytes(data)

        case .connectionClose(let closeFrame):
            try encodeConnectionCloseFrame(closeFrame, to: &writer)

        case .handshakeDone:
            writer.writeByte(0x1e)

        case .datagram(let datagramFrame):
            if datagramFrame.hasLength {
                writer.writeByte(0x31)
                try writeVarint(UInt64(datagramFrame.data.count), to: &writer)
            } else {
                writer.writeByte(0x30)
            }
            writer.writeBytes(datagramFrame.data)
        }
    }

    /// Writes a QUIC varint, re-wrapping wire-overflow as a frame-format error.
    @inline(__always)
    internal func writeVarint(_ value: UInt64, to writer: inout ByteWriter) throws(FrameCodecError) {
        do {
            try writer.writeVarint(value)
        } catch {
            // ByteWriter rejects values above the 2^62-1 varint range.
            throw FrameCodecError.invalidFrameFormat("varint value exceeds QUIC varint range: \(value)")
        }
    }

    /// Encodes an ACK frame.
    internal func encodeAckFrame(_ ack: AckFrame, to writer: inout ByteWriter) throws(FrameCodecError) {
        // Type byte: 0x02 (ACK) or 0x03 (ACK with ECN)
        let hasECN = ack.ecnCounts != nil
        writer.writeByte(hasECN ? 0x03 : 0x02)

        // Largest Acknowledged
        try writeVarint(ack.largestAcknowledged, to: &writer)

        // ACK Delay
        try writeVarint(ack.ackDelay, to: &writer)

        // ACK Range Count (number of Gap and ACK Range fields)
        let rangeCount = ack.ackRanges.isEmpty ? 0 : ack.ackRanges.count - 1
        try writeVarint(UInt64(rangeCount), to: &writer)

        // First ACK Range (from largest acknowledged)
        if let firstRange = ack.ackRanges.first {
            try writeVarint(firstRange.rangeLength, to: &writer)
        } else {
            try writeVarint(UInt64(0), to: &writer)
        }

        // Additional ACK Ranges (Gap + Range pairs)
        let ranges = ack.ackRanges
        if ranges.count > 1 {
            for i in 1..<ranges.count {
                try writeVarint(ranges[i].gap, to: &writer)
                try writeVarint(ranges[i].rangeLength, to: &writer)
            }
        }

        // ECN Counts (if present)
        if let ecn = ack.ecnCounts {
            try writeVarint(ecn.ect0Count, to: &writer)
            try writeVarint(ecn.ect1Count, to: &writer)
            try writeVarint(ecn.ecnCECount, to: &writer)
        }
    }

    /// Encodes a STREAM frame.
    internal func encodeStreamFrame(_ stream: StreamFrame, to writer: inout ByteWriter) throws(FrameCodecError) {
        // Build type byte with flags
        var typeByte: UInt8 = 0x08
        let hasOffset = stream.offset > 0

        if hasOffset { typeByte |= 0x04 }          // OFF bit
        if stream.hasLength { typeByte |= 0x02 }   // LEN bit
        if stream.fin { typeByte |= 0x01 }         // FIN bit

        writer.writeByte(typeByte)
        try writeVarint(stream.streamID, to: &writer)

        if hasOffset {
            try writeVarint(stream.offset, to: &writer)
        }

        // RFC 9000 Section 12.4: If LEN bit is not set, the frame consumes
        // all remaining bytes in the packet and MUST be the last frame.
        // The caller is responsible for ensuring this constraint.
        if stream.hasLength {
            try writeVarint(UInt64(stream.data.count), to: &writer)
        }

        writer.writeBytes(stream.data)
    }

    /// Encodes a CONNECTION_CLOSE frame.
    internal func encodeConnectionCloseFrame(_ close: ConnectionCloseFrame, to writer: inout ByteWriter) throws(FrameCodecError) {
        // Type: 0x1c (transport) or 0x1d (application)
        writer.writeByte(close.isApplicationError ? 0x1d : 0x1c)

        try writeVarint(close.errorCode, to: &writer)

        // Frame Type (only for transport errors)
        if !close.isApplicationError {
            try writeVarint(close.frameType ?? 0, to: &writer)
        }

        // Reason Phrase
        let reasonBytes = [UInt8](close.reasonPhrase.utf8)
        try writeVarint(UInt64(reasonBytes.count), to: &writer)
        writer.writeBytes(reasonBytes)
    }

    // MARK: - Decoding

    /// Decodes a frame from a byte reader.
    public func decode(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let firstByte: UInt8
        do {
            firstByte = try reader.peekUInt8()
        } catch {
            throw FrameCodecError.insufficientData
        }

        // Optimization: Most frame types fit in a single byte (0x00-0x3F).
        // Check if this is a single-byte varint (MSB prefix 00).
        let frameType: UInt64
        if (firstByte & 0xC0) == 0x00 {
            // Single-byte varint: value is the byte itself.
            do { _ = try reader.readUInt8() } catch { throw FrameCodecError.insufficientData }
            frameType = UInt64(firstByte)
        } else {
            // Multi-byte varint for extended frame types.
            frameType = try readVarint(from: &reader)
        }

        // Handle STREAM frames (0x08-0x0f) - type byte contains flags.
        if frameType >= 0x08 && frameType <= 0x0f {
            return try decodeStreamFrame(from: &reader, typeByte: UInt8(frameType))
        }

        switch frameType {
        case 0x00:
            // PADDING - count consecutive padding bytes.
            // PADDING frames coalesce to the end of the packet (RFC 9000 §19.1),
            // so stop the run on end-of-input (peek fails) without swallowing it.
            var count = 1
            paddingRun: while true {
                let next: UInt8
                do {
                    next = try reader.peekUInt8()
                } catch {
                    // End of input: the PADDING run reaches the packet end.
                    break paddingRun
                }
                guard next == 0x00 else {
                    // A non-PADDING byte begins the next frame.
                    break paddingRun
                }
                do { _ = try reader.readUInt8() } catch { throw FrameCodecError.insufficientData }
                count += 1
            }
            return .padding(count: count)

        case 0x01:
            return .ping

        case 0x02, 0x03:
            return try decodeAckFrame(from: &reader, hasECN: frameType == 0x03)

        case 0x04:
            return try decodeResetStreamFrame(from: &reader)

        case 0x05:
            return try decodeStopSendingFrame(from: &reader)

        case 0x06:
            return try decodeCryptoFrame(from: &reader)

        case 0x07:
            return try decodeNewTokenFrame(from: &reader)

        case 0x10:
            let maxData = try readVarint(from: &reader)
            return .maxData(maxData)

        case 0x11:
            return try decodeMaxStreamDataFrame(from: &reader)

        case 0x12, 0x13:
            return try decodeMaxStreamsFrame(from: &reader, isBidi: frameType == 0x12)

        case 0x14:
            let limit = try readVarint(from: &reader)
            return .dataBlocked(limit)

        case 0x15:
            return try decodeStreamDataBlockedFrame(from: &reader)

        case 0x16, 0x17:
            return try decodeStreamsBlockedFrame(from: &reader, isBidi: frameType == 0x16)

        case 0x18:
            return try decodeNewConnectionIDFrame(from: &reader)

        case 0x19:
            let seqNum = try readVarint(from: &reader)
            return .retireConnectionID(seqNum)

        case 0x1a:
            let data: [UInt8]
            do { data = try reader.readBytes(8) } catch { throw FrameCodecError.insufficientData }
            return .pathChallenge(data)

        case 0x1b:
            let data: [UInt8]
            do { data = try reader.readBytes(8) } catch { throw FrameCodecError.insufficientData }
            return .pathResponse(data)

        case 0x1c, 0x1d:
            return try decodeConnectionCloseFrame(from: &reader, isApp: frameType == 0x1d)

        case 0x1e:
            return .handshakeDone

        case 0x30, 0x31:
            return try decodeDatagramFrame(from: &reader, hasLength: frameType == 0x31)

        default:
            // Unknown or extended frame type.
            throw FrameCodecError.unknownFrameType(frameType)
        }
    }

    /// Decodes all frames from a byte array.
    public func decodeFrames(from bytes: [UInt8]) throws(FrameCodecError) -> [Frame] {
        var reader = ByteReader(bytes)
        var frames: [Frame] = []
        var lastFrameHadNoLength = false

        while !reader.isAtEnd {
            // RFC 9000 Section 12.4: Frames without length field must be last.
            if lastFrameHadNoLength {
                throw FrameCodecError.invalidFrameFormat(
                    "Frame without length field must be last in packet"
                )
            }

            let frame = try decode(from: &reader)
            frames.append(frame)

            // Check if this frame consumed remaining bytes without explicit length.
            lastFrameHadNoLength = isFrameWithoutExplicitLength(frame)
        }

        return frames
    }

    /// Checks if a frame consumed remaining bytes without an explicit length field.
    /// Per RFC 9000 Section 12.4, such frames must be the last frame in a packet.
    internal func isFrameWithoutExplicitLength(_ frame: Frame) -> Bool {
        switch frame {
        case .stream(let sf):
            return !sf.hasLength
        case .datagram(let df):
            return !df.hasLength
        default:
            return false
        }
    }

    /// Reads a QUIC varint, re-wrapping insufficient-data as a frame-codec error.
    @inline(__always)
    internal func readVarint(from reader: inout ByteReader) throws(FrameCodecError) -> UInt64 {
        do {
            return try reader.readVarint()
        } catch {
            throw FrameCodecError.insufficientData
        }
    }

    // MARK: - Frame-Specific Decoders

    /// Decodes an ACK frame.
    internal func decodeAckFrame(from reader: inout ByteReader, hasECN: Bool) throws(FrameCodecError) -> Frame {
        let largestAcked = try readVarint(from: &reader)
        let ackDelay = try readVarint(from: &reader)
        let rangeCount = try readVarint(from: &reader)
        let firstRangeLength = try readVarint(from: &reader)

        // Validate rangeCount against remaining data.
        // Each ACK range requires at least 2 bytes (minimum size of 2 varints).
        // Also apply protocol limit to prevent memory exhaustion attacks.
        let maxReasonableRangeCount = min(
            UInt64(reader.remaining / 2),
            ProtocolLimits.maxAckRanges
        )
        guard rangeCount <= maxReasonableRangeCount else {
            throw FrameCodecError.invalidFrameFormat(
                "ACK range count \(rangeCount) exceeds maximum allowed value \(maxReasonableRangeCount)"
            )
        }

        // Pre-allocate array capacity for performance.
        // Safe conversion: rangeCount is validated above to be <= maxAckRanges (256).
        let safeRangeCount: Int
        do {
            safeRangeCount = try SafeConversions.toInt(
                rangeCount,
                maxAllowed: Int(ProtocolLimits.maxAckRanges),
                context: "ACK range count"
            )
        } catch {
            throw FrameCodecError.invalidFrameFormat("ACK range count out of range: \(rangeCount)")
        }
        var ranges: [AckRange] = []
        ranges.reserveCapacity(safeRangeCount + 1)
        ranges.append(AckRange(gap: 0, rangeLength: firstRangeLength))

        for _ in 0..<safeRangeCount {
            let gap = try readVarint(from: &reader)
            let rangeLength = try readVarint(from: &reader)
            ranges.append(AckRange(gap: gap, rangeLength: rangeLength))
        }

        var ecnCounts: ECNCounts? = nil
        if hasECN {
            let ect0 = try readVarint(from: &reader)
            let ect1 = try readVarint(from: &reader)
            let ecnCE = try readVarint(from: &reader)
            ecnCounts = ECNCounts(ect0Count: ect0, ect1Count: ect1, ecnCECount: ecnCE)
        }

        return .ack(AckFrame(
            largestAcknowledged: largestAcked,
            ackDelay: ackDelay,
            ackRanges: ranges,
            ecnCounts: ecnCounts
        ))
    }

    internal func decodeResetStreamFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let streamID = try readVarint(from: &reader)
        let errorCode = try readVarint(from: &reader)
        let finalSize = try readVarint(from: &reader)
        return .resetStream(ResetStreamFrame(
            streamID: streamID,
            applicationErrorCode: errorCode,
            finalSize: finalSize
        ))
    }

    internal func decodeStopSendingFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let streamID = try readVarint(from: &reader)
        let errorCode = try readVarint(from: &reader)
        return .stopSending(StopSendingFrame(
            streamID: streamID,
            applicationErrorCode: errorCode
        ))
    }

    internal func decodeCryptoFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let offset = try readVarint(from: &reader)
        let length = try readVarint(from: &reader)
        let safeLength: Int
        do {
            safeLength = try SafeConversions.toInt(
                length,
                maxAllowed: ProtocolLimits.maxCryptoDataLength,
                context: "CRYPTO frame data length"
            )
        } catch {
            throw FrameCodecError.invalidFrameFormat("CRYPTO frame data length out of range: \(length)")
        }
        // RFC 9000 §19.6 / §7.5: the largest offset delivered on the crypto stream cannot
        // exceed 2^62-1. Reject (offset + length) overflow or out-of-range end offset as a
        // FRAME_ENCODING_ERROR rather than computing a wrapped end offset.
        try Self.validateEndOffsetWithinVarintRange(
            offset: offset,
            length: length,
            context: "CRYPTO frame"
        )
        let data: [UInt8]
        do { data = try reader.readBytes(safeLength) } catch { throw FrameCodecError.insufficientData }
        return .crypto(CryptoFrame(offset: offset, data: data))
    }

    /// Validates that `offset + length` does not overflow and stays within the QUIC
    /// varint range (`<= 2^62 - 1`), per RFC 9000 §4.5 / §7.5.
    ///
    /// Uses `addingReportingOverflow` because both operands originate from untrusted
    /// wire data. A violation is surfaced as a FRAME_ENCODING_ERROR (final offset bound)
    /// rather than being silently truncated.
    internal static func validateEndOffsetWithinVarintRange(
        offset: UInt64,
        length: UInt64,
        context: String
    ) throws(FrameCodecError) {
        let (endOffset, overflow) = offset.addingReportingOverflow(length)
        guard !overflow, endOffset <= Varint.maxValue else {
            throw FrameCodecError.invalidFrameFormat(
                "\(context) final offset exceeds 2^62-1 (offset=\(offset), length=\(length))"
            )
        }
    }

    internal func decodeNewTokenFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let length = try readVarint(from: &reader)
        let safeLength: Int
        do {
            safeLength = try SafeConversions.toInt(
                length,
                maxAllowed: ProtocolLimits.maxNewTokenLength,
                context: "NEW_TOKEN frame token length"
            )
        } catch {
            throw FrameCodecError.invalidFrameFormat("NEW_TOKEN frame token length out of range: \(length)")
        }
        let token: [UInt8]
        do { token = try reader.readBytes(safeLength) } catch { throw FrameCodecError.insufficientData }
        return .newToken(token)
    }

    internal func decodeStreamFrame(from reader: inout ByteReader, typeByte: UInt8) throws(FrameCodecError) -> Frame {
        let hasOffset = (typeByte & 0x04) != 0
        let hasLength = (typeByte & 0x02) != 0
        let hasFin = (typeByte & 0x01) != 0

        let streamID = try readVarint(from: &reader)

        let offset: UInt64
        if hasOffset {
            offset = try readVarint(from: &reader)
        } else {
            offset = 0
        }

        let data: [UInt8]
        if hasLength {
            let length = try readVarint(from: &reader)
            let safeLength: Int
            do {
                safeLength = try SafeConversions.toInt(
                    length,
                    maxAllowed: ProtocolLimits.maxStreamDataLength,
                    context: "STREAM frame data length"
                )
            } catch {
                throw FrameCodecError.invalidFrameFormat("STREAM frame data length out of range: \(length)")
            }
            // RFC 9000 §4.5: the final offset (offset + length) of a stream cannot exceed
            // 2^62-1. Validate before reading bytes so an out-of-range frame is rejected as
            // a FRAME_ENCODING_ERROR instead of producing a wrapped end offset.
            try Self.validateEndOffsetWithinVarintRange(
                offset: offset,
                length: length,
                context: "STREAM frame"
            )
            do { data = try reader.readBytes(safeLength) } catch { throw FrameCodecError.insufficientData }
        } else {
            // No length means data extends to end of packet.
            // Per RFC 9000 Section 12.4, this frame must be last in packet.
            data = reader.readRemaining()
            // Even without an explicit length field, the resulting end offset must remain
            // within the varint range (RFC 9000 §4.5).
            try Self.validateEndOffsetWithinVarintRange(
                offset: offset,
                length: UInt64(data.count),
                context: "STREAM frame"
            )
        }

        return .stream(StreamFrame(
            streamID: streamID,
            offset: offset,
            data: data,
            fin: hasFin,
            hasLength: hasLength
        ))
    }

    internal func decodeMaxStreamDataFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let streamID = try readVarint(from: &reader)
        let maxStreamData = try readVarint(from: &reader)
        return .maxStreamData(MaxStreamDataFrame(
            streamID: streamID,
            maxStreamData: maxStreamData
        ))
    }

    internal func decodeMaxStreamsFrame(from reader: inout ByteReader, isBidi: Bool) throws(FrameCodecError) -> Frame {
        let maxStreams = try readVarint(from: &reader)
        return .maxStreams(MaxStreamsFrame(
            maxStreams: maxStreams,
            isBidirectional: isBidi
        ))
    }

    internal func decodeStreamDataBlockedFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let streamID = try readVarint(from: &reader)
        let limit = try readVarint(from: &reader)
        return .streamDataBlocked(StreamDataBlockedFrame(
            streamID: streamID,
            streamDataLimit: limit
        ))
    }

    internal func decodeStreamsBlockedFrame(from reader: inout ByteReader, isBidi: Bool) throws(FrameCodecError) -> Frame {
        let limit = try readVarint(from: &reader)
        return .streamsBlocked(StreamsBlockedFrame(
            streamLimit: limit,
            isBidirectional: isBidi
        ))
    }

    internal func decodeNewConnectionIDFrame(from reader: inout ByteReader) throws(FrameCodecError) -> Frame {
        let seqNum = try readVarint(from: &reader)
        let retirePriorTo = try readVarint(from: &reader)

        let cidLength: UInt8
        do { cidLength = try reader.readUInt8() } catch { throw FrameCodecError.insufficientData }

        guard cidLength <= ConnectionID.maxLength else {
            throw FrameCodecError.invalidFrameFormat("Connection ID too long: \(cidLength)")
        }

        let cidBytes: [UInt8]
        do { cidBytes = try reader.readBytes(Int(cidLength)) } catch { throw FrameCodecError.insufficientData }

        let resetToken: [UInt8]
        do { resetToken = try reader.readBytes(16) } catch { throw FrameCodecError.insufficientData }

        let connectionID: ConnectionID
        do {
            connectionID = try ConnectionID(bytes: cidBytes)
        } catch {
            throw FrameCodecError.invalidFrameFormat("Invalid connection ID")
        }

        // RFC 9000 §19.15: `retire_prior_to > sequence_number` is a FRAME_ENCODING_ERROR.
        // The structural invariant is enforced by NewConnectionIDFrame's validating init;
        // translate its FrameError into the codec's error domain so callers consistently
        // map it to FRAME_ENCODING_ERROR and reject the frame at decode time, before any
        // retirement loop can run.
        do {
            let frame = try NewConnectionIDFrame(
                sequenceNumber: seqNum,
                retirePriorTo: retirePriorTo,
                connectionID: connectionID,
                statelessResetToken: resetToken
            )
            return .newConnectionID(frame)
        } catch {
            switch error {
            case .retirePriorToExceedsSequenceNumber(let rpt, let seq):
                throw FrameCodecError.invalidFrameFormat(
                    "NEW_CONNECTION_ID retire_prior_to (\(rpt)) > sequence_number (\(seq))"
                )
            case .invalidStatelessResetTokenLength:
                throw FrameCodecError.invalidFrameFormat("Invalid stateless reset token length")
            }
        }
    }

    internal func decodeConnectionCloseFrame(from reader: inout ByteReader, isApp: Bool) throws(FrameCodecError) -> Frame {
        let errorCode = try readVarint(from: &reader)

        var frameType: UInt64? = nil
        if !isApp {
            frameType = try readVarint(from: &reader)
        }

        let reasonLength = try readVarint(from: &reader)
        let reasonPhrase: String
        if reasonLength > 0 {
            let safeLength: Int
            do {
                safeLength = try SafeConversions.toInt(
                    reasonLength,
                    maxAllowed: ProtocolLimits.maxReasonPhraseLength,
                    context: "CONNECTION_CLOSE reason phrase length"
                )
            } catch {
                throw FrameCodecError.invalidFrameFormat("CONNECTION_CLOSE reason phrase length out of range: \(reasonLength)")
            }
            let reasonBytes: [UInt8]
            do { reasonBytes = try reader.readBytes(safeLength) } catch { throw FrameCodecError.insufficientData }
            reasonPhrase = String(decoding: reasonBytes, as: UTF8.self)
        } else {
            reasonPhrase = ""
        }

        return .connectionClose(ConnectionCloseFrame(
            errorCode: errorCode,
            frameType: frameType,
            reasonPhrase: reasonPhrase,
            isApplicationError: isApp
        ))
    }

    internal func decodeDatagramFrame(from reader: inout ByteReader, hasLength: Bool) throws(FrameCodecError) -> Frame {
        let data: [UInt8]
        if hasLength {
            let length = try readVarint(from: &reader)
            let safeLength: Int
            do {
                safeLength = try SafeConversions.toInt(
                    length,
                    maxAllowed: ProtocolLimits.maxDatagramLength,
                    context: "DATAGRAM frame data length"
                )
            } catch {
                throw FrameCodecError.invalidFrameFormat("DATAGRAM frame data length out of range: \(length)")
            }
            do { data = try reader.readBytes(safeLength) } catch { throw FrameCodecError.insufficientData }
        } else {
            data = reader.readRemaining()
        }

        return .datagram(DatagramFrame(data: data, hasLength: hasLength))
    }
}
