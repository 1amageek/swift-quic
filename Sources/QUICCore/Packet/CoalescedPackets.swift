/// QUIC Coalesced Packets (RFC 9000 Section 12.2)
///
/// Multiple QUIC packets can be coalesced into a single UDP datagram.
/// This is particularly useful during connection establishment when
/// Initial, Handshake, and 1-RTT packets may be sent together.

import Foundation

// MARK: - Coalesced Packet Builder

/// Builds a coalesced packet from multiple QUIC packets
public struct CoalescedPacketBuilder: Sendable {
    /// Maximum UDP datagram size
    public let maxDatagramSize: Int

    /// Accumulated packets
    private var packets: [Data]

    /// Current total size
    private var currentSize: Int

    /// Creates a coalesced packet builder
    /// - Parameter maxDatagramSize: Maximum size of the UDP datagram (default: 1200)
    public init(maxDatagramSize: Int = 1200) {
        self.maxDatagramSize = maxDatagramSize
        self.packets = []
        self.currentSize = 0
    }

    /// Adds a packet to the coalesced packet
    /// - Parameter packet: The encoded packet data
    /// - Returns: true if the packet was added, false if it wouldn't fit
    public mutating func addPacket(_ packet: Data) -> Bool {
        guard currentSize + packet.count <= maxDatagramSize else {
            return false
        }
        packets.append(packet)
        currentSize += packet.count
        return true
    }

    /// Returns the number of packets currently added
    public var packetCount: Int {
        packets.count
    }

    /// Returns the current total size
    public var totalSize: Int {
        currentSize
    }

    /// Returns the remaining space in the datagram
    public var remainingSpace: Int {
        maxDatagramSize - currentSize
    }

    /// Whether the builder has any packets
    public var isEmpty: Bool {
        packets.isEmpty
    }

    /// Builds the coalesced packet data
    /// - Returns: The combined packet data
    public func build() -> Data {
        var result = Data(capacity: currentSize)
        for packet in packets {
            result.append(packet)
        }
        return result
    }

    /// Clears all packets
    public mutating func clear() {
        packets.removeAll()
        currentSize = 0
    }
}

// MARK: - Coalesced Packet Parser

/// Parses coalesced packets from a single UDP datagram
public struct CoalescedPacketParser: Sendable {
    /// Errors that can occur during parsing
    public enum ParseError: Error, Sendable {
        case emptyDatagram
        case invalidPacketHeader
        case packetLengthExceedsDatagram
        case insufficientData
    }

    /// Information about a packet found in the datagram
    public struct PacketInfo: Sendable {
        /// The packet data
        public let data: Data
        /// Whether this is a long header packet
        public let isLongHeader: Bool
        /// The offset in the original datagram
        public let offset: Int
    }

    /// Parses all packets from a coalesced datagram
    /// - Parameters:
    ///   - datagram: The UDP datagram data
    ///   - dcidLength: Expected DCID length for short header packets
    /// - Returns: Array of packet info for each packet found
    public static func parse(datagram: Data, dcidLength: Int = 0) throws -> [PacketInfo] {
        guard !datagram.isEmpty else {
            throw ParseError.emptyDatagram
        }

        var packets: [PacketInfo] = []
        var offset = datagram.startIndex

        while offset < datagram.endIndex {
            let firstByte = datagram[offset]
            let isLongHeader = PacketHeader.isLongHeader(firstByte: firstByte)

            // Determine packet length
            let packetLength: Int
            let packetStart = offset

            if isLongHeader {
                // Long header packet - need to parse to find the length
                packetLength = try parseLongHeaderPacketLength(
                    datagram: datagram,
                    startOffset: offset
                )
            } else {
                // Short header packet - consumes rest of datagram
                // Per RFC 9000: "A short header packet always includes
                // a Destination Connection ID following the short header."
                // And: "A short header packet MUST be the last packet
                // included in a UDP datagram."
                packetLength = datagram.endIndex - offset
            }

            guard packetStart + packetLength <= datagram.endIndex else {
                throw ParseError.packetLengthExceedsDatagram
            }

            let packetData = datagram[packetStart..<(packetStart + packetLength)]
            packets.append(PacketInfo(
                data: Data(packetData),
                isLongHeader: isLongHeader,
                offset: packetStart - datagram.startIndex
            ))

            offset = packetStart + packetLength

            // Short header packets must be last
            if !isLongHeader {
                break
            }
        }

        return packets
    }

    /// Parses the length of a long header packet
    private static func parseLongHeaderPacketLength(
        datagram: Data,
        startOffset: Data.Index
    ) throws -> Int {
        var reader = DataReader(datagram)
        // Skip to the start offset
        reader.advance(by: startOffset - datagram.startIndex)

        guard let firstByte = reader.readByte() else {
            throw ParseError.insufficientData
        }

        // Read version
        guard let version = reader.readUInt32() else {
            throw ParseError.insufficientData
        }

        // Check if this is Version Negotiation (version == 0)
        if version == 0 {
            // Version Negotiation packets have no length field
            // They consume the rest of the datagram after the header
            // Header: 1 + 4 + 1 + DCID + 1 + SCID + versions...
            // We need to read DCID and SCID lengths
            guard let dcidLen = reader.readByte() else {
                throw ParseError.insufficientData
            }
            guard reader.readBytes(Int(dcidLen)) != nil else {
                throw ParseError.insufficientData
            }
            guard let scidLen = reader.readByte() else {
                throw ParseError.insufficientData
            }
            guard reader.readBytes(Int(scidLen)) != nil else {
                throw ParseError.insufficientData
            }
            // Version Negotiation consumes the rest
            return datagram.endIndex - startOffset
        }

        // Read DCID
        guard let dcidLen = reader.readByte() else {
            throw ParseError.insufficientData
        }
        guard reader.readBytes(Int(dcidLen)) != nil else {
            throw ParseError.insufficientData
        }

        // Read SCID
        guard let scidLen = reader.readByte() else {
            throw ParseError.insufficientData
        }
        guard reader.readBytes(Int(scidLen)) != nil else {
            throw ParseError.insufficientData
        }

        // Determine packet type
        let packetType = (firstByte >> 4) & 0x03

        switch packetType {
        case 0x00:  // Initial
            // Read token length
            let tokenLength = try reader.readVarint()
            let safeTokenLength = try SafeConversions.toInt(
                tokenLength.value,
                maxAllowed: ProtocolLimits.maxInitialTokenLength,
                context: "Initial packet token length (coalesced)"
            )
            guard reader.readBytes(safeTokenLength) != nil else {
                throw ParseError.insufficientData
            }
            // Read Length field
            let length = try reader.readVarint()
            // Total length: header so far + packet number + payload
            let headerLength = reader.currentPosition - (startOffset - datagram.startIndex)
            let safeLength = try SafeConversions.toInt(
                length.value,
                maxAllowed: ProtocolLimits.maxLongHeaderLength,
                context: "Initial packet length field"
            )
            return try SafeConversions.add(headerLength, safeLength)

        case 0x01:  // 0-RTT
            // Read Length field
            let length = try reader.readVarint()
            let headerLength = reader.currentPosition - (startOffset - datagram.startIndex)
            let safeLength = try SafeConversions.toInt(
                length.value,
                maxAllowed: ProtocolLimits.maxLongHeaderLength,
                context: "0-RTT packet length field"
            )
            return try SafeConversions.add(headerLength, safeLength)

        case 0x02:  // Handshake
            // Read Length field
            let length = try reader.readVarint()
            let headerLength = reader.currentPosition - (startOffset - datagram.startIndex)
            let safeLength = try SafeConversions.toInt(
                length.value,
                maxAllowed: ProtocolLimits.maxLongHeaderLength,
                context: "Handshake packet length field"
            )
            return try SafeConversions.add(headerLength, safeLength)

        case 0x03:  // Retry
            // Retry packets have no Length field
            // They end at the integrity tag (16 bytes at the end)
            // Retry consumes the rest of the datagram
            return datagram.endIndex - startOffset

        default:
            throw ParseError.invalidPacketHeader
        }
    }
}

// MARK: - Convenience Extensions

extension CoalescedPacketBuilder {
    /// Creates a coalesced packet from an array of packet data
    /// - Parameters:
    ///   - packets: Array of encoded packet data
    ///   - maxDatagramSize: Maximum datagram size
    /// - Returns: The coalesced packet data, or nil if no packets fit
    public static func coalesce(
        packets: [Data],
        maxDatagramSize: Int = 1200
    ) -> Data? {
        var builder = CoalescedPacketBuilder(maxDatagramSize: maxDatagramSize)
        for packet in packets {
            if !builder.addPacket(packet) {
                break
            }
        }
        return builder.isEmpty ? nil : builder.build()
    }
}

extension CoalescedPacketParser {
    /// Convenience method to parse and return just the packet data
    /// - Parameters:
    ///   - datagram: The UDP datagram
    ///   - dcidLength: Expected DCID length for short headers
    /// - Returns: Array of packet data
    public static func splitPackets(
        datagram: Data,
        dcidLength: Int = 0
    ) throws -> [Data] {
        try parse(datagram: datagram, dcidLength: dcidLength).map(\.data)
    }
}

// MARK: - Packet Ordering

/// Utility for ordering coalesced packets
public enum CoalescedPacketOrder {
    /// Returns the recommended order for coalescing packets
    ///
    /// RFC 9000 Section 12.2: "Senders SHOULD NOT coalesce QUIC packets
    /// with different connection IDs into a single UDP datagram."
    ///
    /// Order: Initial -> Handshake -> 0-RTT -> 1-RTT
    public static func sortOrder(for packetType: PacketType) -> Int {
        switch packetType {
        case .initial: return 0
        case .handshake: return 1
        case .zeroRTT: return 2
        case .oneRTT: return 3
        case .retry: return 4  // Retry shouldn't be coalesced
        case .versionNegotiation: return 5  // VN shouldn't be coalesced
        }
    }

    /// Sorts packets by recommended coalescing order
    /// - Parameter packets: Array of (packetType, packetData) tuples
    /// - Returns: Sorted array
    public static func sort(
        packets: [(packetType: PacketType, data: Data)]
    ) -> [(packetType: PacketType, data: Data)] {
        packets.sorted { sortOrder(for: $0.packetType) < sortOrder(for: $1.packetType) }
    }
}
