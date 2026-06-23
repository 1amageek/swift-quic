/// QUIC Loss Detection (RFC 9002 Section 6)
///
/// Detects lost packets using packet threshold and time threshold criteria.
///
/// ## Caller-locked core
///
/// The RFC 9002 §6 loss-detection state machine lives in the Embedded-clean value
/// type `QUICRecoveryCore.LossDetectorCore`, which operates on a sorted array of
/// `SentPacketView` with time injected as monotonic `UInt64` nanoseconds. This class
/// is the host adapter: it keeps the `Mutex`, fixes a `ContinuousClock` epoch,
/// decodes the wire `AckFrame`'s gap/rangeLength encoding into the `[AckInterval]`
/// the core consumes, projects each `SentPacket` into a `SentPacketView` (carrying
/// the host `SentPacket` in a side map so results can be reconstructed exactly), and
/// converts emitted deadlines back to `ContinuousClock.Instant`. Public API and
/// observable behavior are unchanged.

import Foundation
import Synchronization
import QUICCore
import QUICRecoveryCore

/// Loss detection for a single packet number space (RFC 9002)
public final class LossDetector: Sendable {
    private let state: Mutex<AdapterState>

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    /// Caller-locked state: the value-type core plus the host-side side table that
    /// maps packet numbers to the original `SentPacket`s (so acked/lost results and
    /// retransmission/probe queries return the exact host objects the caller stored).
    private struct AdapterState {
        var core: LossDetectorCore
        var packets: [UInt64: SentPacket]
    }

    /// Creates a new LossDetector
    public init() {
        self.epoch = ContinuousClock.now
        self.state = Mutex(AdapterState(core: LossDetectorCore(), packets: [:]))
    }

    /// Records a sent packet
    /// - Parameter packet: The sent packet to track
    public func onPacketSent(_ packet: SentPacket) {
        let nanos = MonotonicNanos.nanos(from: epoch, to: packet.timeSent)
        let view = SentPacketView(
            packetNumber: packet.packetNumber,
            timeSentNanos: nanos,
            sentBytes: packet.sentBytes,
            inFlight: packet.inFlight,
            ackEliciting: packet.ackEliciting
        )
        state.withLock { s in
            s.packets[packet.packetNumber] = packet
            s.core.onPacketSent(view)
        }
    }

    /// Processes acknowledgments and detects losses
    /// - Parameters:
    ///   - ackFrame: The received ACK frame
    ///   - ackReceivedTime: When the ACK was received
    ///   - rttEstimator: The RTT estimator to update
    /// - Returns: Result containing acknowledged and lost packets
    ///
    /// ## RFC 9002 Compliance
    /// - largestAckedPacket is only updated after successful ACK processing
    /// - RTT sample is taken from the largest newly acknowledged ack-eliciting packet
    /// - isFirstAckElicitingAck is set only when an ack-eliciting packet is actually acknowledged
    public func onAckReceived(
        ackFrame: AckFrame,
        ackReceivedTime: ContinuousClock.Instant,
        rttEstimator: RTTEstimator
    ) -> LossDetectionResult {
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: ackReceivedTime)
        let latestNanos = MonotonicNanos.nanos(of: rttEstimator.latestRTT)
        let smoothedNanos = MonotonicNanos.nanos(of: rttEstimator.smoothedRTT)

        // Decode the wire gap/rangeLength encoding into concrete intervals adapter-side
        // (bounded by the ACK frame's own ranges, then by our sent packets in the core).
        let intervals = Self.computeAckIntervals(
            ranges: ackFrame.ackRanges,
            largestAcked: ackFrame.largestAcknowledged
        )

        let (ackedHost, lostHost, rttSampleNanos, isFirstAckElicitingAck):
            ([SentPacket], [SentPacket], UInt64?, Bool) =
            state.withLock { s in
                let wasFirstAck = s.core.largestAckedPacket == nil

                let r = s.core.onAckReceived(
                    largestAcked: ackFrame.largestAcknowledged,
                    intervals: intervals,
                    wasFirstAck: wasFirstAck,
                    nowNanos: nowNanos,
                    latestRTTNanos: latestNanos,
                    smoothedRTTNanos: smoothedNanos
                )

                var acked: [SentPacket] = []
                acked.reserveCapacity(r.acked.count)
                for view in r.acked {
                    if let host = s.packets.removeValue(forKey: view.packetNumber) {
                        acked.append(host)
                    }
                }

                var lost: [SentPacket] = []
                lost.reserveCapacity(r.lost.count)
                for view in r.lost {
                    if let host = s.packets.removeValue(forKey: view.packetNumber) {
                        lost.append(host)
                    }
                }

                // Prune stale non-in-flight packets the core removed (not reported
                // as lost) so the side table cannot leak.
                for pn in r.droppedNonInFlight {
                    s.packets.removeValue(forKey: pn)
                }

                return (acked, lost, r.rttSampleNanos, r.isFirstAckElicitingAck)
            }

        let rttSample: Duration? = rttSampleNanos.map { .nanoseconds(Int64(clamping: $0)) }

        // Decode ack delay (already in microseconds after frame decoding)
        let ackDelay = Duration.microseconds(Int64(ackFrame.ackDelay))

        return LossDetectionResult(
            ackedPackets: ackedHost,
            lostPackets: lostHost,
            rttSample: rttSample,
            ackDelay: ackDelay,
            isFirstAckElicitingAck: isFirstAckElicitingAck
        )
    }

    /// Computes ACK intervals from ACK ranges (RFC 9000 Section 19.3.1).
    ///
    /// - First range: `[largestAcked - firstRange.rangeLength, largestAcked]`
    /// - Subsequent ranges: the gap indicates unacked packets below the previous range.
    ///
    /// Returns intervals sorted by start (descending), matching the core's expectation.
    private static func computeAckIntervals(ranges: [AckRange], largestAcked: UInt64) -> [AckInterval] {
        var intervals: [AckInterval] = []
        intervals.reserveCapacity(ranges.count)

        var current = largestAcked

        for (index, range) in ranges.enumerated() {
            let rangeEnd: UInt64
            let rangeStart: UInt64

            if index == 0 {
                rangeEnd = current
                guard range.rangeLength <= current else { break }
                rangeStart = current - range.rangeLength
            } else {
                let gapOffset = range.gap + 2
                guard gapOffset <= current else { break }
                current = current - gapOffset
                rangeEnd = current
                guard range.rangeLength <= current else { break }
                rangeStart = current - range.rangeLength
            }

            intervals.append(AckInterval(start: rangeStart, end: rangeEnd))
            current = rangeStart
        }

        return intervals
    }

    /// Detects losses due to timeout
    /// - Parameters:
    ///   - now: Current time
    ///   - rttEstimator: The RTT estimator
    /// - Returns: Packets detected as lost
    public func detectLostPackets(
        now: ContinuousClock.Instant,
        rttEstimator: RTTEstimator
    ) -> [SentPacket] {
        let nowNanos = MonotonicNanos.nanos(from: epoch, to: now)
        let latestNanos = MonotonicNanos.nanos(of: rttEstimator.latestRTT)
        let smoothedNanos = MonotonicNanos.nanos(of: rttEstimator.smoothedRTT)

        return state.withLock { s in
            let lossResult = s.core.detectLostPackets(
                nowNanos: nowNanos,
                latestRTTNanos: latestNanos,
                smoothedRTTNanos: smoothedNanos
            )
            var lost: [SentPacket] = []
            lost.reserveCapacity(lossResult.lost.count)
            for view in lossResult.lost {
                if let host = s.packets.removeValue(forKey: view.packetNumber) {
                    lost.append(host)
                }
            }
            for pn in lossResult.droppedNonInFlight {
                s.packets.removeValue(forKey: pn)
            }
            return lost
        }
    }

    /// Gets the earliest loss time for timer scheduling
    public func earliestLossTime() -> ContinuousClock.Instant? {
        state.withLock { s in
            guard let nanos = s.core.lossTimeNanos else { return nil }
            return MonotonicNanos.instant(from: epoch, nanos: nanos)
        }
    }

    /// Gets packets that need retransmission (ack-eliciting packets still in flight)
    public func getRetransmittablePackets() -> [SentPacket] {
        state.withLock { s in
            let views = s.core.retransmittablePackets()
            var result: [SentPacket] = []
            result.reserveCapacity(views.count)
            for view in views {
                if let host = s.packets[view.packetNumber] {
                    result.append(host)
                }
            }
            return result
        }
    }

    /// Gets the current bytes in flight
    public var bytesInFlight: Int {
        state.withLock { $0.core.bytesInFlight }
    }

    /// Gets the count of ack-eliciting packets in flight
    public var ackElicitingInFlight: Int {
        state.withLock { $0.core.ackElicitingInFlight }
    }

    /// Gets the largest acknowledged packet number
    public var largestAckedPacket: UInt64? {
        state.withLock { $0.core.largestAckedPacket }
    }

    /// Gets the smallest unacked packet number
    public var smallestUnacked: UInt64? {
        state.withLock { $0.core.smallestUnacked }
    }

    /// Gets the oldest unacknowledged ack-eliciting packets for PTO probing
    ///
    /// RFC 9002 Section 6.2: When PTO expires, send probe packets.
    /// The probe SHOULD carry data from the oldest unacked packet.
    ///
    /// - Parameter count: Maximum number of packets to return (typically 2)
    /// - Returns: Oldest unacked ack-eliciting packets, sorted by packet number
    public func getOldestUnackedPackets(count: Int) -> [SentPacket] {
        state.withLock { s in
            let views = s.core.oldestUnackedPackets(count: count)
            var result: [SentPacket] = []
            result.reserveCapacity(views.count)
            for view in views {
                if let host = s.packets[view.packetNumber] {
                    result.append(host)
                }
            }
            return result
        }
    }

    /// Clears state (called when encryption level is discarded)
    public func clear() {
        state.withLock { s in
            s.core.clear()
            s.packets.removeAll(keepingCapacity: true)
        }
    }
}
