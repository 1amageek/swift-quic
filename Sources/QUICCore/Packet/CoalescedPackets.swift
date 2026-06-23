/// QUIC Coalesced Packets (RFC 9000 Section 12.2)
///
/// Multiple QUIC packets can be coalesced into a single UDP datagram.
/// This is particularly useful during connection establishment when
/// Initial, Handshake, and 1-RTT packets may be sent together.

import Foundation
import QUICConnectionCore

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
        // Pre-allocate for typical case of 2-3 coalesced packets
        self.packets = []
        self.packets.reserveCapacity(3)
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
    ///
    /// Boundary computation (and the 1.3.0 token/Length security bounds and the
    /// short-header-MUST-be-last rule) is performed by the Embedded-clean
    /// ``CoalescedDatagramCore``. This adapter keeps the historical `Data`-slice
    /// `PacketInfo` output (copy-on-write slices, no allocation per packet) and
    /// rewraps the core's typed error onto `ParseError`.
    public static func parse(datagram: Data, dcidLength: Int = 0) throws -> [PacketInfo] {
        let ranges: [CoalescedPacketRange]
        do {
            ranges = try CoalescedDatagramCore.split(
                datagram: [UInt8](datagram),
                dcidLength: dcidLength
            )
        } catch {
            switch error {
            case .emptyDatagram:
                throw ParseError.emptyDatagram
            case .invalidPacketHeader:
                throw ParseError.invalidPacketHeader
            case .packetLengthExceedsDatagram:
                throw ParseError.packetLengthExceedsDatagram
            case .insufficientData:
                throw ParseError.insufficientData
            }
        }

        var packets: [PacketInfo] = []
        packets.reserveCapacity(ranges.count)
        for range in ranges {
            // Map the core's datagram-relative offset back onto the Data slice
            // indices, preserving copy-on-write (no per-packet allocation).
            let packetStart = datagram.startIndex + range.offset
            let packetData = datagram[packetStart..<(packetStart + range.length)]
            packets.append(PacketInfo(
                data: packetData,
                isLongHeader: range.isLongHeader,
                offset: range.offset
            ))
        }
        return packets
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
