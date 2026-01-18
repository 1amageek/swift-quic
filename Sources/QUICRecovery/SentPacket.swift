/// Sent Packet Tracking (RFC 9002)
///
/// Tracks sent packets for loss detection and acknowledgment management.

import Foundation
import QUICCore

/// Tracks a sent packet for loss detection (RFC 9002 Appendix A.1.1)
public struct SentPacket: Sendable, Identifiable {
    /// Unique identifier (packet number)
    public let id: UInt64

    /// Alias for packet number
    public var packetNumber: UInt64 { id }

    /// Encryption level this packet belongs to
    public let encryptionLevel: EncryptionLevel

    /// Time the packet was sent
    public let timeSent: ContinuousClock.Instant

    /// Whether this packet contains ack-eliciting frames
    public let ackEliciting: Bool

    /// Whether this packet is in-flight (counts against congestion window)
    public let inFlight: Bool

    /// Size of the packet in bytes (for congestion control)
    public let sentBytes: Int

    /// Frames contained in this packet (for potential retransmission)
    public let frames: [Frame]

    /// Creates a new SentPacket
    /// - Parameters:
    ///   - packetNumber: The packet number
    ///   - encryptionLevel: The encryption level
    ///   - timeSent: When the packet was sent
    ///   - ackEliciting: Whether the packet requires an ACK
    ///   - inFlight: Whether the packet counts toward bytes in flight
    ///   - sentBytes: Size of the packet in bytes
    ///   - frames: Frames contained in the packet
    public init(
        packetNumber: UInt64,
        encryptionLevel: EncryptionLevel,
        timeSent: ContinuousClock.Instant,
        ackEliciting: Bool,
        inFlight: Bool,
        sentBytes: Int,
        frames: [Frame]
    ) {
        self.id = packetNumber
        self.encryptionLevel = encryptionLevel
        self.timeSent = timeSent
        self.ackEliciting = ackEliciting
        self.inFlight = inFlight
        self.sentBytes = sentBytes
        self.frames = frames
    }
}

/// Result of processing an ACK frame
public struct LossDetectionResult: Sendable {
    /// Packets that were newly acknowledged
    public let ackedPackets: [SentPacket]

    /// Packets detected as lost
    public let lostPackets: [SentPacket]

    /// RTT sample if applicable (from largest newly acked packet)
    public let rttSample: Duration?

    /// The ack delay reported by peer
    public let ackDelay: Duration

    /// Whether this is the first ACK that acknowledges an ack-eliciting packet
    public let isFirstAckElicitingAck: Bool

    public init(
        ackedPackets: [SentPacket],
        lostPackets: [SentPacket],
        rttSample: Duration?,
        ackDelay: Duration,
        isFirstAckElicitingAck: Bool = false
    ) {
        self.ackedPackets = ackedPackets
        self.lostPackets = lostPackets
        self.rttSample = rttSample
        self.ackDelay = ackDelay
        self.isFirstAckElicitingAck = isFirstAckElicitingAck
    }

    /// Empty result (no packets acknowledged or lost)
    public static let empty = LossDetectionResult(
        ackedPackets: [],
        lostPackets: [],
        rttSample: nil,
        ackDelay: .zero
    )
}

/// Tracks a received packet for ACK generation
public struct ReceivedPacket: Sendable {
    /// The packet number
    public let packetNumber: UInt64

    /// Time the packet was received
    public let receiveTime: ContinuousClock.Instant

    /// Whether this packet was ack-eliciting
    public let ackEliciting: Bool

    public init(
        packetNumber: UInt64,
        receiveTime: ContinuousClock.Instant,
        ackEliciting: Bool
    ) {
        self.packetNumber = packetNumber
        self.receiveTime = receiveTime
        self.ackEliciting = ackEliciting
    }
}
