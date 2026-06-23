/// QUIC RTT Estimation (RFC 9002 Section 5)
///
/// Round-trip time estimation for loss detection and congestion control.
///
/// ## Caller-locked core
///
/// The RFC 9002 §5 EWMA state machine lives in the Embedded-clean value type
/// `QUICRecoveryCore.RTTEstimatorCore`, which operates purely on monotonic `UInt64`
/// nanoseconds. This `struct` is the host adapter: it keeps the same `Duration`-typed
/// public surface, converts `Duration` to/from nanoseconds, and delegates the math to
/// the core. Public API and observable behavior are unchanged.

import Foundation
import QUICRecoveryCore

// MARK: - RTT Estimator

/// Estimates round-trip time for a QUIC connection
public struct RTTEstimator: Sendable {
    /// The Embedded-clean RFC 9002 §5 EWMA state machine (nanoseconds).
    private var core: RTTEstimatorCore

    /// Minimum RTT observed
    public var minRTT: Duration { .nanoseconds(Int64(clamping: core.minRTTNanos)) }

    /// Smoothed RTT (EWMA)
    public var smoothedRTT: Duration { .nanoseconds(Int64(clamping: core.smoothedRTTNanos)) }

    /// RTT variance
    public var rttVariance: Duration { .nanoseconds(Int64(clamping: core.rttVarianceNanos)) }

    /// Latest RTT sample
    public var latestRTT: Duration { .nanoseconds(Int64(clamping: core.latestRTTNanos)) }

    /// Whether we have received at least one RTT sample
    public var hasEstimate: Bool { core.hasEstimate }

    /// Initial RTT (used before first sample)
    public static let initialRTT: Duration = .milliseconds(333)

    /// Creates a new RTT estimator
    public init() {
        self.core = RTTEstimatorCore()
    }

    /// Updates the RTT estimate with a new sample
    ///
    /// RFC 9002 Section 5.3: The ack_delay is used to adjust the RTT sample,
    /// but only after the handshake is confirmed. Before handshake confirmation,
    /// the ack_delay is not applied because the peer may not yet be using its
    /// final max_ack_delay value.
    ///
    /// - Parameters:
    ///   - rttSample: The new RTT sample
    ///   - ackDelay: The acknowledgment delay reported by the peer
    ///   - maxAckDelay: The peer's max_ack_delay transport parameter
    ///   - handshakeConfirmed: Whether the handshake has been confirmed
    public mutating func updateRTT(
        rttSample: Duration,
        ackDelay: Duration,
        maxAckDelay: Duration,
        handshakeConfirmed: Bool
    ) {
        core.update(
            latestRttNanos: MonotonicNanos.nanos(of: rttSample),
            ackDelayNanos: MonotonicNanos.nanos(of: ackDelay),
            maxAckDelayNanos: MonotonicNanos.nanos(of: maxAckDelay),
            handshakeConfirmed: handshakeConfirmed
        )
    }

    /// Calculates the Probe Timeout (PTO) value
    /// - Parameter maxAckDelay: The peer's max_ack_delay transport parameter
    /// - Returns: The PTO duration
    public func probeTimeout(maxAckDelay: Duration) -> Duration {
        // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        let ptoNanos = core.probeTimeoutNanos(maxAckDelayNanos: MonotonicNanos.nanos(of: maxAckDelay))
        return .nanoseconds(Int64(clamping: ptoNanos))
    }
}

// MARK: - Duration Extensions

extension Duration {
    /// Divides a duration by an integer
    /// Note: +, - operators exist in standard library, but * and / with Int do not
    static func / (lhs: Duration, rhs: Int) -> Duration {
        let (seconds, attoseconds) = lhs.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return .nanoseconds(totalNs / Int64(rhs))
    }

    /// Multiplies a duration by an integer
    static func * (lhs: Duration, rhs: Int) -> Duration {
        let (seconds, attoseconds) = lhs.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return .nanoseconds(totalNs * Int64(rhs))
    }

    /// Absolute value of a duration
    static func abs(_ duration: Duration) -> Duration {
        let (seconds, attoseconds) = duration.components
        let totalNs = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        if totalNs < 0 {
            return .nanoseconds(-totalNs)
        }
        return duration
    }
}
