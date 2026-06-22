/// The minimal RTT view a value-type congestion controller needs.
///
/// The host `RTTEstimator` stores `Duration` values; this core consumes only the
/// smoothed RTT (as monotonic nanoseconds) and whether an estimate exists. The
/// adapter projects its `RTTEstimator` into this snapshot before calling the core.
///
/// Embedded-clean: no Foundation, no `Duration`, no `ContinuousClock`.
public struct RTTSnapshot: Sendable, Equatable {
    /// Whether at least one RTT sample has been recorded.
    public let hasEstimate: Bool

    /// Smoothed RTT in nanoseconds (meaningful only when `hasEstimate` is true).
    public let smoothedRTTNanos: UInt64

    /// Creates an RTT snapshot.
    @inline(__always)
    public init(hasEstimate: Bool, smoothedRTTNanos: UInt64) {
        self.hasEstimate = hasEstimate
        self.smoothedRTTNanos = smoothedRTTNanos
    }
}

/// The per-packet information a value-type congestion controller consumes.
///
/// The host `SentPacket` carries a `ContinuousClock.Instant`; this core consumes
/// only the byte count, the monotonic send time as nanoseconds, and the in-flight
/// flag. The adapter projects each `SentPacket` into this view.
public struct CongestionPacket: Sendable, Equatable {
    /// Packet size in bytes (the unit of congestion-window accounting).
    public let sentBytes: Int

    /// Send time as injected monotonic nanoseconds.
    public let timeSentNanos: UInt64

    /// Whether the packet counts against the congestion window.
    public let inFlight: Bool

    /// Creates a congestion-control packet view.
    @inline(__always)
    public init(sentBytes: Int, timeSentNanos: UInt64, inFlight: Bool) {
        self.sentBytes = sentBytes
        self.timeSentNanos = timeSentNanos
        self.inFlight = inFlight
    }
}
