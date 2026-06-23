/// QUIC coalesced-datagram splitting — Embedded-clean core (RFC 9000 §12.2).
///
/// Multiple QUIC packets can be coalesced into one UDP datagram. Splitting a
/// received datagram into its constituent packets is pure parsing: it inspects
/// header fields and the long-header Length field to find each packet boundary,
/// with no crypto, no I/O, and no mutable state. `CoalescedDatagramCore` moves
/// that logic onto `[UInt8]`/`ByteReader`; the host adapter
/// `CoalescedPacketParser` keeps its `Data`-slice output and delegates the
/// boundary computation here.
///
/// The 1.3.0 security bounds are preserved exactly: the long-header packet
/// length is bounded by `SafeConversions`/`ProtocolLimits` (token and Length
/// fields), boundaries are checked against the datagram extent, and a short
/// header always terminates the datagram (RFC 9000 §12.2 — a short-header packet
/// MUST be the last packet in a UDP datagram).
///
/// Embedded-clean: no Foundation, no `any`, no crypto, no `Mutex`; typed throws
/// (``CoalescedDatagramError``); no silent fallback.

import P2PCoreBytes
import QUICCoreCodec

/// Error thrown while splitting a coalesced datagram.
public enum CoalescedDatagramError: Error, Sendable, Equatable {
    /// The datagram was empty.
    case emptyDatagram
    /// A long-header packet's structure was malformed.
    case invalidPacketHeader
    /// A computed packet length ran past the datagram boundary.
    case packetLengthExceedsDatagram
    /// Not enough bytes remained to compute a packet boundary.
    case insufficientData
}

/// One packet located inside a coalesced datagram, expressed as a byte range.
public struct CoalescedPacketRange: Sendable, Equatable {
    /// Whether this packet uses a long header.
    public let isLongHeader: Bool
    /// The offset of the packet's first byte within the datagram.
    public let offset: Int
    /// The packet's length in bytes.
    public let length: Int

    public init(isLongHeader: Bool, offset: Int, length: Int) {
        self.isLongHeader = isLongHeader
        self.offset = offset
        self.length = length
    }
}

/// Pure coalesced-datagram splitter (RFC 9000 §12.2).
public enum CoalescedDatagramCore {

    /// Splits a coalesced datagram into the byte ranges of its packets.
    ///
    /// - Parameters:
    ///   - datagram: The full UDP datagram bytes.
    ///   - dcidLength: Expected DCID length for the (final) short-header packet.
    /// - Returns: The packet ranges in datagram order.
    public static func split(
        datagram: [UInt8],
        dcidLength: Int
    ) throws(CoalescedDatagramError) -> [CoalescedPacketRange] {
        guard !datagram.isEmpty else {
            throw .emptyDatagram
        }

        var ranges: [CoalescedPacketRange] = []
        ranges.reserveCapacity(3)
        var offset = 0
        let end = datagram.count

        while offset < end {
            let firstByte = datagram[offset]
            let isLongHeader = (firstByte & 0x80) != 0

            let packetLength: Int
            if isLongHeader {
                packetLength = try longHeaderPacketLength(datagram: datagram, startOffset: offset)
            } else {
                // Short-header packet consumes the rest of the datagram and MUST be last.
                packetLength = end - offset
            }

            guard offset + packetLength <= end else {
                throw .packetLengthExceedsDatagram
            }

            ranges.append(CoalescedPacketRange(
                isLongHeader: isLongHeader,
                offset: offset,
                length: packetLength
            ))

            offset += packetLength

            // RFC 9000 §12.2: a short-header packet MUST be the last packet in a datagram.
            if !isLongHeader {
                break
            }
        }

        return ranges
    }

    /// Computes the on-wire length of a single long-header packet starting at
    /// `startOffset`, enforcing the 1.3.0 token/Length bounds.
    private static func longHeaderPacketLength(
        datagram: [UInt8],
        startOffset: Int
    ) throws(CoalescedDatagramError) -> Int {
        // A sub-reader over the packet slice so offsets are relative to its start.
        var reader = ByteReader(Array(datagram[startOffset...]))
        let sliceCount = datagram.count - startOffset

        let firstByte: UInt8
        let version: UInt32
        do {
            firstByte = try reader.readUInt8()
            version = try reader.readUInt32()
        } catch {
            throw .insufficientData
        }

        // Version Negotiation (version == 0): no Length field, consumes the rest
        // after DCID + SCID.
        if version == 0 {
            do {
                try skipConnectionID(&reader)
                try skipConnectionID(&reader)
            } catch {
                throw error
            }
            return sliceCount
        }

        do {
            try skipConnectionID(&reader)   // DCID
            try skipConnectionID(&reader)   // SCID
        } catch {
            throw error
        }

        let packetType = (firstByte >> 4) & 0x03
        switch packetType {
        case 0x00:  // Initial
            // Token length + token, then Length field.
            let tokenLength: UInt64
            do { tokenLength = try reader.readVarint() } catch { throw .insufficientData }
            let safeTokenLength: Int
            do {
                safeTokenLength = try SafeConversions.toInt(
                    tokenLength,
                    maxAllowed: ProtocolLimits.maxInitialTokenLength,
                    context: "Initial packet token length (coalesced)"
                )
            } catch {
                throw .invalidPacketHeader
            }
            do { try reader.skip(safeTokenLength) } catch { throw .insufficientData }
            return try longHeaderTotalLength(&reader, context: "Initial packet length field")

        case 0x01:  // 0-RTT
            return try longHeaderTotalLength(&reader, context: "0-RTT packet length field")

        case 0x02:  // Handshake
            return try longHeaderTotalLength(&reader, context: "Handshake packet length field")

        case 0x03:  // Retry
            // Retry has no Length field; it consumes the rest of the datagram.
            return sliceCount

        default:
            throw .invalidPacketHeader
        }
    }

    /// Reads the long-header Length varint and returns `headerBytesRead + length`,
    /// bounding the Length field per the 1.3.0 limits.
    private static func longHeaderTotalLength(
        _ reader: inout ByteReader,
        context: String
    ) throws(CoalescedDatagramError) -> Int {
        let length: UInt64
        do { length = try reader.readVarint() } catch { throw .insufficientData }
        let safeLength: Int
        do {
            safeLength = try SafeConversions.toInt(
                length,
                maxAllowed: ProtocolLimits.maxLongHeaderLength,
                context: context
            )
        } catch {
            throw .invalidPacketHeader
        }
        do {
            return try SafeConversions.add(reader.position, safeLength)
        } catch {
            throw .invalidPacketHeader
        }
    }

    /// Skips a length-prefixed connection ID (1 length byte + that many bytes).
    private static func skipConnectionID(_ reader: inout ByteReader) throws(CoalescedDatagramError) {
        let length: UInt8
        do { length = try reader.readUInt8() } catch { throw .insufficientData }
        do { try reader.skip(Int(length)) } catch { throw .insufficientData }
    }
}
