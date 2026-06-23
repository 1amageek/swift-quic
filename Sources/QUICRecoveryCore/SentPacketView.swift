/// The per-packet information the value-type loss detector tracks.
///
/// The host `SentPacket` carries a `ContinuousClock.Instant` and an
/// `EncryptionLevel`; this view carries only what RFC 9002 §6 loss detection needs,
/// with the send time as injected monotonic nanoseconds. The host adapter projects
/// each `SentPacket` into this view (and back, by carrying the host `SentPacket`
/// alongside the core).
///
/// Embedded-clean: no Foundation, no `ContinuousClock`, no `EncryptionLevel`.
public struct SentPacketView: Sendable, Equatable {

    /// Packet number (the loss-detection key).
    public let packetNumber: UInt64

    /// Send time as injected monotonic nanoseconds.
    public let timeSentNanos: UInt64

    /// Packet size in bytes (the unit of in-flight accounting).
    public let sentBytes: Int

    /// Whether this packet counts against bytes-in-flight / the congestion window.
    public let inFlight: Bool

    /// Whether this packet contains ack-eliciting frames.
    public let ackEliciting: Bool

    /// Creates a sent-packet view.
    @inline(__always)
    public init(
        packetNumber: UInt64,
        timeSentNanos: UInt64,
        sentBytes: Int,
        inFlight: Bool,
        ackEliciting: Bool
    ) {
        self.packetNumber = packetNumber
        self.timeSentNanos = timeSentNanos
        self.sentBytes = sentBytes
        self.inFlight = inFlight
        self.ackEliciting = ackEliciting
    }
}

/// A single acknowledged packet-number range, expressed as an inclusive interval.
///
/// The host adapter decodes the wire `AckFrame`'s gap/rangeLength encoding into these
/// concrete `[start, end]` intervals (sorted by start descending, non-overlapping)
/// before handing them to the loss-detector core, so the core never sees the
/// attacker-controllable gap encoding directly.
public struct AckInterval: Sendable, Equatable {

    /// Smallest acknowledged packet number in this range (inclusive).
    public let start: UInt64

    /// Largest acknowledged packet number in this range (inclusive).
    public let end: UInt64

    /// Creates an acknowledged interval.
    @inline(__always)
    public init(start: UInt64, end: UInt64) {
        self.start = start
        self.end = end
    }
}
