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
/// `NewRenoCongestionController` so it is a drop-in replacement.
///
/// ## Caller-locked core
///
/// The RFC 9438 state machine lives in the Embedded-clean value type
/// `QUICRecoveryCore.CubicCore`. This class is the host adapter: it keeps the
/// `Mutex`, fixes a `ContinuousClock` epoch, converts `Instant`/`Duration` to the
/// monotonic `UInt64` nanoseconds the core consumes, and delegates the math under
/// the lock. Public API and observable behavior are unchanged.

import Foundation
import Synchronization
import QUICRecoveryCore

/// CUBIC congestion controller with integrated pacing (RFC 9438).
///
/// Uses `class + Mutex` design for high-frequency updates (per-packet operations),
/// matching `NewRenoCongestionController`. This avoids actor hop overhead while
/// maintaining thread safety.
public final class CubicCongestionController: CongestionController, Sendable {

    // MARK: - Internal State

    private let state: Mutex<AdapterState>

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    /// Caller-locked state: the value-type core plus the host-only shadow needed to
    /// reconstruct `ContinuousClock.Instant`s exactly for the public API.
    private struct AdapterState {
        /// The Embedded-clean RFC 9438 state machine.
        var core: CubicCore
        /// The original recovery-start `Instant` (exact round-trip for `currentState`).
        var recoveryStartInstant: ContinuousClock.Instant?
    }

    // MARK: - Initialization

    /// Creates a new CUBIC congestion controller.
    ///
    /// - Parameter maxDatagramSize: Maximum datagram size in bytes (default: 1200).
    public init(maxDatagramSize: Int = LossDetectionConstants.maxDatagramSize) {
        self.epoch = ContinuousClock.now
        self.state = Mutex(AdapterState(
            core: CubicCore(maxDatagramSize: maxDatagramSize),
            recoveryStartInstant: nil
        ))
    }

    // MARK: - CongestionController Protocol

    public var congestionWindow: Int {
        state.withLock { $0.core.clampedWindow }
    }

    public var currentState: CongestionState {
        state.withLock { s in
            switch s.core.state {
            case .recovery:
                // Reconstruct the exact recovery-start instant from the shadow.
                if let recoveryStart = s.recoveryStartInstant {
                    return .recovery(startTime: recoveryStart)
                }
                return .recovery(startTime: epoch)
            case .slowStart:
                return .slowStart
            case .congestionAvoidance:
                return .congestionAvoidance
            }
        }
    }

    public func availableWindow(bytesInFlight: Int) -> Int {
        state.withLock { $0.core.availableWindow(bytesInFlight: bytesInFlight) }
    }

    // MARK: - Pacing

    public func nextSendTime() -> ContinuousClock.Instant? {
        state.withLock { s in
            guard let nanos = s.core.nextSendNanosOrImmediate else { return nil }
            return MonotonicNanos.instant(from: epoch, nanos: nanos)
        }
    }

    // MARK: - Event Handlers

    public func onPacketSent(bytes: Int, now: ContinuousClock.Instant) {
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: now)
        state.withLock { $0.core.onPacketSent(bytes: bytes, nowNanos: nowNanos) }
    }

    public func onPacketsAcknowledged(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        let corePackets = packets.map { corePacket($0) }
        let snapshot = rttSnapshot(rtt)
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: now)
        state.withLock { s in
            s.core.onPacketsAcknowledged(packets: corePackets, nowNanos: nowNanos, rtt: snapshot)
            if s.core.recoveryStartNanos == nil {
                s.recoveryStartInstant = nil
            }
        }
    }

    public func onPacketsLost(
        packets: [SentPacket],
        now: ContinuousClock.Instant,
        rtt: RTTEstimator
    ) {
        let corePackets = packets.map { corePacket($0) }
        let snapshot = rttSnapshot(rtt)
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: now)
        state.withLock { s in
            let wasInRecovery = s.core.recoveryStartNanos != nil
            s.core.onPacketsLost(packets: corePackets, nowNanos: nowNanos, rtt: snapshot)
            if !wasInRecovery, s.core.recoveryStartNanos != nil {
                s.recoveryStartInstant = now
            }
        }
    }

    public func onECNCongestionEvent(now: ContinuousClock.Instant) {
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: now)
        state.withLock { s in
            let wasInRecovery = s.core.recoveryStartNanos != nil
            s.core.onECNCongestionEvent(nowNanos: nowNanos)
            if !wasInRecovery, s.core.recoveryStartNanos != nil {
                s.recoveryStartInstant = now
            }
        }
    }

    public func onPersistentCongestion() {
        state.withLock { s in
            s.core.onPersistentCongestion()
            s.recoveryStartInstant = nil
        }
    }

    public func updateMaxDatagramSize(_ maxDatagramSize: Int) {
        state.withLock { $0.core.updateMaxDatagramSize(maxDatagramSize) }
    }

    // MARK: - Projection helpers

    /// Projects a host `SentPacket` into the Embedded-clean `CongestionPacket`.
    private func corePacket(_ packet: SentPacket) -> CongestionPacket {
        CongestionPacket(
            sentBytes: packet.sentBytes,
            timeSentNanos: MonotonicNanos.nanos(from: epoch, to: packet.timeSent),
            inFlight: packet.inFlight
        )
    }

    /// Projects a host `RTTEstimator` into the Embedded-clean `RTTSnapshot`.
    private func rttSnapshot(_ rtt: RTTEstimator) -> RTTSnapshot {
        RTTSnapshot(
            hasEstimate: rtt.hasEstimate,
            smoothedRTTNanos: MonotonicNanos.nanos(of: rtt.smoothedRTT)
        )
    }
}

// MARK: - Debug Support

extension CubicCongestionController: CustomStringConvertible {

    public var description: String {
        state.withLock { $0.core.description }
    }
}
