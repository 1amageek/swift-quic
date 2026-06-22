/// QUIC NewReno Congestion Controller (RFC 9002 Section 7)
///
/// Implements the NewReno congestion control algorithm with integrated pacing.
/// This is the default and recommended algorithm for QUIC implementations.
///
/// ## Algorithm Overview
///
/// NewReno operates in three phases:
/// 1. **Slow Start**: Exponential window growth (cwnd += bytes_acked)
/// 2. **Congestion Avoidance**: Linear growth (cwnd += max_datagram_size per RTT)
/// 3. **Recovery**: Window halved, wait for post-recovery ACK
///
/// ## Pacing
///
/// To prevent bursty transmission that can overwhelm network buffers,
/// this implementation includes pacing:
/// - pacing_rate = cwnd / smoothed_rtt
/// - Initial burst tokens allow immediate sending at connection start
///
/// ## Caller-locked core
///
/// The RFC 9002 §7 state machine lives in the Embedded-clean value type
/// `QUICRecoveryCore.NewRenoCore`. This class is the host adapter: it keeps the
/// `Mutex`, fixes a `ContinuousClock` epoch, converts `Instant`/`Duration` to the
/// monotonic `UInt64` nanoseconds the core consumes, and delegates the math under
/// the lock. Public API and observable behavior are unchanged.

import Foundation
import Synchronization
import QUICRecoveryCore

/// NewReno congestion controller with integrated pacing
///
/// Uses `class + Mutex` design for high-frequency updates (per-packet operations).
/// This avoids actor hop overhead while maintaining thread safety.
public final class NewRenoCongestionController: CongestionController, Sendable {

    // MARK: - Internal State

    private let state: Mutex<AdapterState>

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    /// Caller-locked state: the value-type core plus the host-only shadow needed to
    /// reconstruct `ContinuousClock.Instant`s exactly for the public API.
    private struct AdapterState {
        /// The Embedded-clean RFC 9002 §7 state machine.
        var core: NewRenoCore
        /// The original recovery-start `Instant` (exact round-trip for `currentState`).
        var recoveryStartInstant: ContinuousClock.Instant?
    }

    // MARK: - Initialization

    /// Creates a new NewReno congestion controller
    ///
    /// - Parameter maxDatagramSize: Maximum datagram size in bytes (default: 1200)
    public init(maxDatagramSize: Int = LossDetectionConstants.maxDatagramSize) {
        self.epoch = ContinuousClock.now
        self.state = Mutex(AdapterState(
            core: NewRenoCore(maxDatagramSize: maxDatagramSize),
            recoveryStartInstant: nil
        ))
    }

    // MARK: - CongestionController Protocol

    public var congestionWindow: Int {
        state.withLock { $0.core.congestionWindow }
    }

    public var currentState: CongestionState {
        state.withLock { s in
            if let recoveryStart = s.recoveryStartInstant {
                return .recovery(startTime: recoveryStart)
            } else if s.core.congestionWindow < s.core.ssthresh {
                return .slowStart
            } else {
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
        state.withLock { s in
            s.core.onPacketsAcknowledged(packets: corePackets, rtt: snapshot)
            // Exiting recovery clears the shadow instant in lockstep with the core.
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

extension NewRenoCongestionController: CustomStringConvertible {

    public var description: String {
        state.withLock { $0.core.description }
    }
}
