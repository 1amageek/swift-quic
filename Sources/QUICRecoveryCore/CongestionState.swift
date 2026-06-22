/// The phase of a congestion controller, expressed Embedded-cleanly.
///
/// This mirrors the host-side `CongestionState` but expresses the recovery start
/// time as an injected monotonic `UInt64` nanosecond value rather than a
/// `ContinuousClock.Instant`. The host adapter maps `recovery(startNanos:)` back to
/// `.recovery(startTime: ContinuousClock.Instant)` for its public API.
///
/// Embedded-clean: no Foundation, no `ContinuousClock`.

/// The current phase of a value-type congestion controller.
public enum CongestionCoreState: Sendable, Equatable {
    /// Slow start: exponential window growth while `cwnd < ssthresh`.
    case slowStart

    /// Congestion avoidance: cubic / linear growth.
    case congestionAvoidance

    /// Recovery: entered on a congestion event; carries the recovery start time as
    /// injected monotonic nanoseconds.
    case recovery(startNanos: UInt64)
}
