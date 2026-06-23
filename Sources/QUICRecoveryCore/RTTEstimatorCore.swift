/// Embedded-clean RTT estimator (RFC 9002 §5) as a value type.
///
/// This is the byte-identical EWMA math of the host `RTTEstimator`, expressed as a
/// `struct` operating purely on monotonic `UInt64` nanosecond values. The host
/// `RTTEstimator` keeps `Duration`-typed public fields and a `RTTEstimatorCore`; it
/// converts `Duration` to/from nanoseconds and delegates the math here, so observable
/// behavior is unchanged.
///
/// All durations are stored as nanoseconds. The arithmetic is integer
/// (`Int64`/`UInt64`-nanosecond) throughout, matching the prior host implementation,
/// so the smoothed-RTT / variance / min-RTT updates are numerically identical.
///
/// Embedded-clean: no Foundation, no `Duration`, no `ContinuousClock`, no `any`,
/// no `Mutex`.
public struct RTTEstimatorCore: Sendable, Equatable {

    // MARK: - State (all nanoseconds)

    /// Minimum RTT observed, in nanoseconds.
    public private(set) var minRTTNanos: UInt64

    /// Smoothed RTT (EWMA), in nanoseconds.
    public private(set) var smoothedRTTNanos: UInt64

    /// RTT variance, in nanoseconds.
    public private(set) var rttVarianceNanos: UInt64

    /// Latest RTT sample, in nanoseconds.
    public private(set) var latestRTTNanos: UInt64

    /// Whether at least one RTT sample has been recorded.
    public private(set) var hasEstimate: Bool

    // MARK: - Constants

    /// Initial RTT estimate in nanoseconds (RFC 9002 §5.1: 333 ms).
    public static let initialRTTNanos: UInt64 = 333_000_000

    /// Timer granularity in nanoseconds (RFC 9002 §6.1.2: 1 ms).
    public static let granularityNanos: UInt64 = 1_000_000

    // MARK: - Initialization

    /// Creates an RTT estimator core in the RFC 9002 §5.1 pre-sample state:
    /// smoothed RTT = 333 ms, variance = 166.5 ms, min/latest = 0, no estimate.
    public init() {
        self.minRTTNanos = 0
        self.smoothedRTTNanos = Self.initialRTTNanos
        self.rttVarianceNanos = Self.initialRTTNanos / 2
        self.latestRTTNanos = 0
        self.hasEstimate = false
    }

    // MARK: - Update

    /// Updates the RTT estimate with a new sample (RFC 9002 §5.2 / §5.3).
    ///
    /// The ack delay is subtracted (capped at `maxAckDelayNanos`) only after the
    /// handshake is confirmed, and only when the result stays above `min_rtt`.
    ///
    /// The integer arithmetic here is `rttvar = (3 * rttvar + |smoothed - adjusted|) / 4`
    /// and `smoothed = (7 * smoothed + adjusted) / 8`, matching the prior host path.
    ///
    /// - Parameters:
    ///   - latestRttNanos: The new RTT sample in nanoseconds.
    ///   - ackDelayNanos: The peer-reported ack delay in nanoseconds.
    ///   - maxAckDelayNanos: The peer's max_ack_delay transport parameter in ns.
    ///   - handshakeConfirmed: Whether the handshake has been confirmed.
    public mutating func update(
        latestRttNanos: UInt64,
        ackDelayNanos: UInt64,
        maxAckDelayNanos: UInt64,
        handshakeConfirmed: Bool
    ) {
        latestRTTNanos = latestRttNanos

        if !hasEstimate {
            // First RTT sample.
            hasEstimate = true
            minRTTNanos = latestRttNanos
            smoothedRTTNanos = latestRttNanos
            rttVarianceNanos = latestRttNanos / 2
            return
        }

        // Update minimum RTT.
        if latestRttNanos < minRTTNanos {
            minRTTNanos = latestRttNanos
        }

        var adjusted = latestRttNanos

        // Adjust for ack delay only after the handshake is confirmed.
        // RFC 9002 §5.3: do not subtract the ack delay if the result would be
        // smaller than min_rtt.
        if handshakeConfirmed {
            let cappedAckDelay = ackDelayNanos < maxAckDelayNanos ? ackDelayNanos : maxAckDelayNanos
            if adjusted > minRTTNanos &+ cappedAckDelay {
                adjusted = latestRttNanos - cappedAckDelay
            }
        }

        // EWMA update (RFC 9002 §5.3):
        //   rttvar   = 3/4 * rttvar + 1/4 * |smoothed - adjusted|
        //   smoothed = 7/8 * smoothed + 1/8 * adjusted
        let diff = smoothedRTTNanos >= adjusted
            ? smoothedRTTNanos - adjusted
            : adjusted - smoothedRTTNanos
        rttVarianceNanos = (rttVarianceNanos &* 3 &+ diff) / 4
        smoothedRTTNanos = (smoothedRTTNanos &* 7 &+ adjusted) / 8
    }

    // MARK: - Probe Timeout

    /// Computes the Probe Timeout (PTO) in nanoseconds (RFC 9002 §6.2.1).
    ///
    /// `PTO = smoothed_rtt + max(4 * rttvar, kGranularity) + max_ack_delay`.
    ///
    /// - Parameter maxAckDelayNanos: The peer's max_ack_delay in nanoseconds.
    /// - Returns: The PTO duration in nanoseconds.
    public func probeTimeoutNanos(maxAckDelayNanos: UInt64) -> UInt64 {
        let fourVar = rttVarianceNanos &* 4
        let k = fourVar > Self.granularityNanos ? fourVar : Self.granularityNanos
        return smoothedRTTNanos &+ k &+ maxAckDelayNanos
    }
}
