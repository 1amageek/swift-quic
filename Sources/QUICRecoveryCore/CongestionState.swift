/// The phase of a congestion controller, expressed Embedded-cleanly.
///
/// Recovery start time is an injected monotonic `UInt64` nanosecond value, so
/// the state does not own or read a clock.
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
