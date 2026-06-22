/// QUIC CUBIC Congestion Controller (RFC 9438)
///
/// Implements the CUBIC congestion control algorithm with integrated pacing.
/// CUBIC is the default and most widely deployed congestion controller for QUIC
/// and TCP; it grows the window along a cubic function of the time since the last
/// congestion event, which makes it efficient on high bandwidth-delay-product paths
/// while remaining fair to Reno on shorter ones.
///
/// ## Algorithm Overview (RFC 9438)
///
/// CUBIC operates in three phases:
/// 1. **Slow Start**: Exponential window growth (cwnd += bytes_acked), identical to
///    NewReno. Active while cwnd < ssthresh.
/// 2. **Congestion Avoidance**: The window follows the cubic function
///    `W_cubic(t) = C * (t - K)^3 + W_max`, where `t` is the elapsed time since the
///    last congestion event, `W_max` is the window at the last congestion event,
///    `C` is a scaling constant (0.4), and `K = cbrt(W_max * (1 - beta_cubic) / C)`.
///    A Reno-friendly (TCP-friendly) estimate runs in parallel and is used whenever
///    it would grow the window faster, so CUBIC is never slower than Reno.
/// 3. **Recovery**: On a congestion event the window is multiplicatively decreased by
///    `beta_cubic` (0.7) and `W_max` is recorded. Fast convergence (RFC 9438 §4.7)
///    lowers `W_max` further when the window shrinks across consecutive events so
///    competing flows can claim the freed capacity.
///
/// ## Pacing (RFC 9002 §7.7)
///
/// The controller maintains the same `nextSendTime` pacing interface as
/// `NewRenoCongestionController` so it is a drop-in replacement. The pacing rate is
/// derived from cwnd and the smoothed RTT, with an initial burst of tokens to allow
/// immediate transmission at connection start.

import Foundation
import Synchronization

/// CUBIC congestion controller with integrated pacing (RFC 9438).
///
/// Uses `class + Mutex` design for high-frequency updates (per-packet operations),
/// matching `NewRenoCongestionController`. This avoids actor hop overhead while
/// maintaining thread safety. All window arithmetic uses `Double` byte counts so the
/// cubic curve can be evaluated precisely; the public `congestionWindow` is the
/// rounded, clamped integer byte count.
public final class CubicCongestionController: CongestionController, Sendable {

    // MARK: - CUBIC Constants (RFC 9438 §4 and §5)

    /// CUBIC scaling constant `C` (RFC 9438 §5): determines the aggressiveness of
    /// window growth in the cubic region. The RFC recommends 0.4.
    private static let cubicC: Double = 0.4

    /// CUBIC multiplicative decrease factor `beta_cubic` (RFC 9438 §4.6).
    /// On a congestion event the window is reduced to `beta_cubic * cwnd`.
    private static let cubicBeta: Double = 0.7

    // MARK: - Internal State

    private let state: Mutex<CCState>

    /// Internal state protected by Mutex.
    ///
    /// Byte counts that participate in the cubic curve (`congestionWindow`,
    /// `wMax`, `wLastMax`, `wEstReno`, `bytesAcked`) are kept as `Double` so the
    /// `(t - K)^3` evaluation does not accumulate integer rounding error.
    private struct CCState: Sendable {
        // RFC 9002 Section 7.1 / RFC 9438 §4 state variables.
        /// Current congestion window in bytes (fractional, clamped at read time).
        var congestionWindow: Double
        /// Slow-start threshold in bytes. `Double.greatestFiniteMagnitude` ~ infinity.
        var ssthresh: Double
        /// Recovery period start time, or nil when not in recovery.
        var recoveryStartTime: ContinuousClock.Instant?

        // CUBIC-specific state (RFC 9438 §4).
        /// `W_max`: window size just before the last congestion event.
        var wMax: Double
        /// `W_last_max`: `W_max` from the previous congestion event, used for fast
        /// convergence (RFC 9438 §4.7).
        var wLastMax: Double
        /// `K`: time period to reach `W_max` again, in seconds (RFC 9438 §4.2).
        var k: Double
        /// Time of the last congestion event; the cubic curve is evaluated relative
        /// to this instant. Nil until the first congestion event.
        var epochStart: ContinuousClock.Instant?
        /// `W_est`: the Reno-friendly window estimate (RFC 9438 §4.3).
        var wEstReno: Double
        /// Accumulated acked bytes used by the Reno-friendly estimator (AIMD).
        var bytesAcked: Double

        // Pacing state (mirrors NewRenoCongestionController).
        var nextSendTime: ContinuousClock.Instant
        var pacingRate: Double  // bytes per nanosecond
        var burstTokens: Int

        // Configuration. `maxDatagramSize` / `minimumWindow` track the path MTU and may be
        // raised by DPLPMTUD (RFC 9000 §14) via updateMaxDatagramSize(_:).
        var maxDatagramSize: Int
        var minimumWindow: Int
    }

    // MARK: - Initialization

    /// Creates a new CUBIC congestion controller.
    ///
    /// - Parameter maxDatagramSize: Maximum datagram size in bytes (default: 1200).
    public init(maxDatagramSize: Int = LossDetectionConstants.maxDatagramSize) {
        let minimumWindow = 2 * maxDatagramSize
        // RFC 9002 Section 7.2: Initial window calculation (shared with NewReno).
        let initialWindow = min(
            10 * maxDatagramSize,
            max(14720, 2 * maxDatagramSize)
        )

        self.state = Mutex(CCState(
            congestionWindow: Double(initialWindow),
            ssthresh: Double.greatestFiniteMagnitude,
            recoveryStartTime: nil,
            wMax: 0,
            wLastMax: 0,
            k: 0,
            epochStart: nil,
            wEstReno: 0,
            bytesAcked: 0,
            nextSendTime: .now,
            pacingRate: 0,
            burstTokens: LossDetectionConstants.initialBurstTokens,
            maxDatagramSize: maxDatagramSize,
            minimumWindow: minimumWindow
        ))
    }

    // MARK: - CongestionController Protocol

    public var congestionWindow: Int {
        state.withLock { Self.clampedWindow($0) }
    }

    public var currentState: CongestionState {
        state.withLock { s in
            if let recoveryStart = s.recoveryStartTime {
                return .recovery(startTime: recoveryStart)
            } else if s.congestionWindow < s.ssthresh {
                return .slowStart
            } else {
                return .congestionAvoidance
            }
        }
    }

    public func availableWindow(bytesInFlight: Int) -> Int {
        state.withLock { s in
            max(0, Self.clampedWindow(s) - bytesInFlight)
        }
    }

    // MARK: - Pacing

    public func nextSendTime() -> ContinuousClock.Instant? {
        state.withLock { s in
            // Burst tokens allow immediate sending at connection start.
            if s.burstTokens > 0 {
                return nil
            }
            // If pacing rate is not yet established, allow immediate sending.
            if s.pacingRate <= 0 {
                return nil
            }
            return s.nextSendTime
        }
    }

    // MARK: - Event Handlers

    public func onPacketSent(bytes: Int, now: ContinuousClock.Instant) {
        state.withLock { s in
            if s.burstTokens > 0 {
                s.burstTokens -= 1
            } else if s.pacingRate > 0 {
                // interval = bytes / pacingRate (in nanoseconds).
                let intervalNanos = Double(bytes) / s.pacingRate
                let nanos = Int64(intervalNanos)
                s.nextSendTime = now + .nanoseconds(nanos)
            }
        }
    }

    public func onPacketsAcknowledged(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        state.withLock { s in
            for packet in packets {
                // Only in-flight packets affect congestion control.
                guard packet.inFlight else { continue }

                // During recovery: only count packets sent AFTER recovery started.
                if let recoveryStart = s.recoveryStartTime {
                    if packet.timeSent <= recoveryStart {
                        // Ignore ACKs of packets sent before recovery; they are
                        // already accounted for in the congestion event.
                        continue
                    }
                    // A packet sent during recovery was acknowledged: exit recovery
                    // and resume congestion avoidance. The CUBIC epoch is left intact
                    // so the curve continues from the congestion event.
                    s.recoveryStartTime = nil
                }

                let acked = Double(packet.sentBytes)

                if s.congestionWindow < s.ssthresh {
                    // Slow start: exponential growth, identical to NewReno.
                    s.congestionWindow += acked
                } else {
                    // Congestion avoidance: cubic growth with a Reno-friendly floor.
                    Self.cubicCongestionAvoidance(&s, ackedBytes: acked, now: now, rtt: rtt)
                }
            }

            updatePacingRate(&s, rtt: rtt)
        }
    }

    public func onPacketsLost(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        guard !packets.isEmpty else { return }

        state.withLock { s in
            // RFC 9002 Section 7.3.2: only one window reduction per RTT. If already
            // in recovery, do not reduce again.
            if s.recoveryStartTime != nil {
                return
            }

            enterRecovery(&s, now: now)
            updatePacingRate(&s, rtt: rtt)
        }
    }

    public func onECNCongestionEvent(now: ContinuousClock.Instant) {
        state.withLock { s in
            // ECN-CE is treated the same as packet loss.
            if s.recoveryStartTime != nil {
                return
            }
            enterRecovery(&s, now: now)
        }
    }

    public func onPersistentCongestion() {
        state.withLock { s in
            // RFC 9002 Section 7.6.2: Persistent Congestion.
            //
            // Collapse cwnd to the minimum window and re-enter slow start. All CUBIC
            // epoch state is reset so the curve restarts from scratch, treating the
            // network as a brand-new path (TCP RTO equivalent).
            s.congestionWindow = Double(s.minimumWindow)
            s.ssthresh = Double.greatestFiniteMagnitude
            s.wMax = 0
            s.wLastMax = 0
            s.k = 0
            s.epochStart = nil
            s.wEstReno = 0
            s.bytesAcked = 0
            s.recoveryStartTime = nil
            s.burstTokens = LossDetectionConstants.initialBurstTokens
            s.pacingRate = 0
        }
    }

    public func updateMaxDatagramSize(_ maxDatagramSize: Int) {
        state.withLock { s in
            // RFC 9000 §14 / RFC 9002 §7.2: track the (raised) path MTU. Only ever raise the
            // datagram size and the minimum-window floor; never shrink the current window.
            guard maxDatagramSize > s.maxDatagramSize else { return }
            s.maxDatagramSize = maxDatagramSize
            s.minimumWindow = 2 * maxDatagramSize
        }
    }

    // MARK: - Private Helpers

    /// Returns the congestion window as a clamped integer byte count.
    ///
    /// Never reports a window below the minimum (2 * max_datagram_size).
    private static func clampedWindow(_ s: CCState) -> Int {
        max(s.minimumWindow, Int(s.congestionWindow.rounded()))
    }

    /// Enters recovery on a congestion event and applies the CUBIC multiplicative
    /// decrease with fast convergence (RFC 9438 §4.6, §4.7).
    private func enterRecovery(_ s: inout CCState, now: ContinuousClock.Instant) {
        s.recoveryStartTime = now

        let cwnd = s.congestionWindow

        // Fast convergence (RFC 9438 §4.7): if the window is shrinking relative to the
        // previous congestion event, lower W_max further so competing flows can grab
        // the released bandwidth more quickly.
        if cwnd < s.wLastMax {
            s.wLastMax = cwnd
            s.wMax = cwnd * (1.0 + Self.cubicBeta) / 2.0
        } else {
            s.wLastMax = cwnd
            s.wMax = cwnd
        }

        // Multiplicative decrease: cwnd = beta_cubic * cwnd, never below the minimum.
        let reduced = cwnd * Self.cubicBeta
        let minWindow = Double(s.minimumWindow)
        s.congestionWindow = max(reduced, minWindow)
        s.ssthresh = max(reduced, minWindow)

        // Reset the cubic epoch; it restarts on the next congestion-avoidance ACK.
        s.epochStart = nil
        // Seed the Reno-friendly estimate at the reduced window.
        s.wEstReno = s.congestionWindow
        s.bytesAcked = 0
    }

    /// Performs one congestion-avoidance step using the cubic curve and the
    /// Reno-friendly estimate (RFC 9438 §4.1–§4.4).
    private static func cubicCongestionAvoidance(
        _ s: inout CCState,
        ackedBytes: Double,
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        let mss = Double(s.maxDatagramSize)

        // Establish the cubic epoch on the first ACK after a congestion event
        // (RFC 9438 §4.2). When W_max has not been set yet (no prior loss), grow
        // toward the current window and use K = 0 so the curve grows immediately.
        if s.epochStart == nil {
            s.epochStart = now
            if s.wMax < s.congestionWindow {
                // No congestion event recorded above the current window: keep the
                // origin at the current window (K = 0) per RFC 9438 §4.2.
                s.k = 0
                s.wMax = s.congestionWindow
            } else {
                // K = cbrt(W_max * (1 - beta_cubic) / C), in seconds.
                s.k = cbrt(s.wMax * (1.0 - cubicBeta) / cubicC)
            }
            s.wEstReno = s.congestionWindow
            s.bytesAcked = 0
        }

        // Elapsed time since the epoch start, in seconds.
        let elapsed = now - (s.epochStart ?? now)
        let t = Double(elapsed.components.seconds)
            + Double(elapsed.components.attoseconds) / 1e18

        // RFC 9438 §4.1: W_cubic(t) = C * (t - K)^3 + W_max.
        let tMinusK = t - s.k
        let wCubic = cubicC * (tMinusK * tMinusK * tMinusK) + s.wMax

        // RFC 9438 §4.3: Reno-friendly region (AIMD estimate). W_est grows by
        // (mss * acked / cwnd) per ACK; equivalently +mss per cwnd bytes acked.
        s.bytesAcked += ackedBytes
        if s.bytesAcked >= s.congestionWindow {
            s.wEstReno += mss
            s.bytesAcked -= s.congestionWindow
        }

        // RFC 9438 §4.2: target increase toward W_cubic over the next RTT.
        // target = clamp(W_cubic(t + RTT)) and translate to a per-cwnd increment.
        let rttSeconds: Double
        if rtt.hasEstimate {
            rttSeconds = Double(rtt.smoothedRTT.components.seconds)
                + Double(rtt.smoothedRTT.components.attoseconds) / 1e18
        } else {
            rttSeconds = 0
        }
        let tNext = (t + rttSeconds) - s.k
        let wCubicNext = cubicC * (tNext * tNext * tNext) + s.wMax

        // Determine the cubic target for the next RTT (RFC 9438 §4.2 "target").
        let target: Double
        if wCubicNext < s.congestionWindow {
            target = s.congestionWindow
        } else if wCubicNext > 1.5 * s.congestionWindow {
            // Limit growth to at most 1.5x cwnd per RTT.
            target = 1.5 * s.congestionWindow
        } else {
            target = wCubicNext
        }

        // Per-ACK cubic increment: (target - cwnd) / cwnd * acked.
        let cubicIncrement: Double
        if s.congestionWindow > 0 {
            cubicIncrement = (target - s.congestionWindow) / s.congestionWindow * ackedBytes
        } else {
            cubicIncrement = 0
        }

        // RFC 9438 §4.3: use the Reno-friendly estimate when it is larger, so CUBIC
        // is never slower than Reno (the TCP-friendly region). Otherwise use the
        // cubic increment.
        if s.wEstReno > wCubic {
            // Reno-friendly region: grow toward W_est.
            let renoIncrement = max(0, s.wEstReno - s.congestionWindow)
            s.congestionWindow += renoIncrement
        } else {
            // Concave / convex cubic region.
            s.congestionWindow += max(0, cubicIncrement)
        }
    }

    /// Updates the pacing rate based on the current cwnd and RTT (RFC 9002 §7.7).
    private func updatePacingRate(_ s: inout CCState, rtt: RTTEstimator) {
        guard rtt.hasEstimate else { return }

        // pacing_rate = cwnd / smoothed_rtt (in bytes per nanosecond).
        let smoothedNanos = rtt.smoothedRTT.components.seconds * 1_000_000_000 +
                            rtt.smoothedRTT.components.attoseconds / 1_000_000_000

        if smoothedNanos > 0 {
            s.pacingRate = Double(Self.clampedWindow(s)) / Double(smoothedNanos)
        }
    }
}

// MARK: - Debug Support

extension CubicCongestionController: CustomStringConvertible {

    public var description: String {
        state.withLock { s in
            let stateStr: String
            if s.recoveryStartTime != nil {
                stateStr = "recovery"
            } else if s.congestionWindow < s.ssthresh {
                stateStr = "slow_start"
            } else {
                stateStr = "congestion_avoidance"
            }
            let cwnd = Self.clampedWindow(s)
            let ssthresh = s.ssthresh == Double.greatestFiniteMagnitude
                ? "inf"
                : String(Int(s.ssthresh.rounded()))
            return "CUBIC(cwnd=\(cwnd), ssthresh=\(ssthresh), wMax=\(Int(s.wMax.rounded())), state=\(stateStr))"
        }
    }
}
