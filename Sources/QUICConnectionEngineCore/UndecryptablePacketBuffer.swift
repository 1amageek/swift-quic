import NetworkingCore
import QUICWire

/// Bounded ownership for protected packets that arrive before their read keys.
///
/// The receive API borrows each datagram, so retaining a packet for RFC 9001
/// section 5.7 replay requires exactly one copy. The buffer is deliberately
/// bounded by both packet count and byte count before peer authentication.
struct UndecryptablePacketBuffer: Sendable {
    struct Packet: Sendable {
        let bytes: [UInt8]
        let level: EncryptionLevel
        let isLongHeader: Bool
        let receivedAtNanos: UInt64
    }

    private static let maximumPacketCount = 32
    private static let maximumByteCount = 64 * 1024

    private var packets: [Packet] = []
    private var byteCount = 0

    var count: Int { packets.count }

    mutating func append(
        _ bytes: Span<UInt8>,
        level: EncryptionLevel,
        isLongHeader: Bool,
        receivedAtNanos: UInt64
    ) {
        guard bytes.count <= Self.maximumByteCount,
              packets.count < Self.maximumPacketCount,
              byteCount <= Self.maximumByteCount - bytes.count else {
            return
        }

        var owned = [UInt8]()
        owned.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            owned.append(bytes[index])
            index += 1
        }
        packets.append(Packet(
            bytes: owned,
            level: level,
            isLongHeader: isLongHeader,
            receivedAtNanos: receivedAtNanos
        ))
        byteCount += owned.count
    }

    mutating func take(level: EncryptionLevel) -> [Packet] {
        var matching: [Packet] = []
        var retained: [Packet] = []
        matching.reserveCapacity(packets.count)
        retained.reserveCapacity(packets.count)

        var retainedBytes = 0
        for packet in packets {
            if packet.level == level {
                matching.append(packet)
            } else {
                retainedBytes += packet.bytes.count
                retained.append(packet)
            }
        }
        packets = retained
        byteCount = retainedBytes
        return matching
    }

    mutating func discard(level: EncryptionLevel) {
        _ = take(level: level)
    }

    mutating func removeAll() {
        packets.removeAll(keepingCapacity: false)
        byteCount = 0
    }
}
