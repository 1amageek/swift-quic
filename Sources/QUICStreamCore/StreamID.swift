/// QUIC Stream ID utilities (RFC 9000 Section 2.1)
///
/// Pure value-type helpers for classifying QUIC stream IDs by direction and
/// initiator. The low two bits of a stream ID encode its type:
///   - bit 0x01: initiator (0 = client, 1 = server)
///   - bit 0x02: directionality (0 = bidirectional, 1 = unidirectional)
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

/// Utilities for working with QUIC stream IDs.
public enum StreamID {
    /// Stream type based on ID.
    public enum StreamType: Sendable {
        case clientInitiatedBidirectional
        case serverInitiatedBidirectional
        case clientInitiatedUnidirectional
        case serverInitiatedUnidirectional
    }

    /// Gets the stream type from a stream ID.
    public static func streamType(for id: UInt64) -> StreamType {
        switch id & 0x03 {
        case 0x00: return .clientInitiatedBidirectional
        case 0x01: return .serverInitiatedBidirectional
        case 0x02: return .clientInitiatedUnidirectional
        default: return .serverInitiatedUnidirectional
        }
    }

    /// Whether the stream is bidirectional.
    public static func isBidirectional(_ id: UInt64) -> Bool {
        (id & 0x02) == 0
    }

    /// Whether the stream is unidirectional.
    public static func isUnidirectional(_ id: UInt64) -> Bool {
        (id & 0x02) != 0
    }

    /// Whether the stream was initiated by the client.
    public static func isClientInitiated(_ id: UInt64) -> Bool {
        (id & 0x01) == 0
    }

    /// Whether the stream was initiated by the server.
    public static func isServerInitiated(_ id: UInt64) -> Bool {
        (id & 0x01) != 0
    }

    /// Creates a stream ID.
    /// - Parameters:
    ///   - index: The stream index (0, 1, 2, ...).
    ///   - isClient: Whether this is a client-initiated stream.
    ///   - isBidirectional: Whether this is a bidirectional stream.
    public static func make(index: UInt64, isClient: Bool, isBidirectional: Bool) -> UInt64 {
        var id = index << 2
        if !isClient { id |= 0x01 }
        if !isBidirectional { id |= 0x02 }
        return id
    }
}
