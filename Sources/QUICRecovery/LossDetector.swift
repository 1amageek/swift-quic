/// QUIC Loss Detection (RFC 9002 Section 4)
///
/// Detects lost packets using packet threshold and time threshold criteria.
/// Optimized for efficient ACK processing and loss detection.

import Foundation
import Synchronization
import QUICCore

/// Loss detection for a single packet number space (RFC 9002)
public final class LossDetector: Sendable {
    private let state: Mutex<LossState>

    private struct LossState {
        /// Sent packets awaiting acknowledgment, keyed by packet number
        /// Initial capacity of 128 to reduce rehashing during normal operation
        var sentPackets: [UInt64: SentPacket]

        /// Largest packet number acknowledged
        var largestAckedPacket: UInt64?

        /// Time when loss timer should fire
        var lossTime: ContinuousClock.Instant?

        /// Bytes in flight
        var bytesInFlight: Int = 0

        /// Ack-eliciting packets in flight
        var ackElicitingInFlight: Int = 0

        /// Smallest unacked packet number (for fast iteration)
        var smallestUnacked: UInt64?

        init() {
            // Pre-allocate capacity to reduce rehashing
            // Typical QUIC connections have <1000 packets in flight
            self.sentPackets = Dictionary(minimumCapacity: 128)
        }
    }

    /// Creates a new LossDetector
    public init() {
        self.state = Mutex(LossState())
    }

    /// Records a sent packet
    /// - Parameter packet: The sent packet to track
    public func onPacketSent(_ packet: SentPacket) {
        state.withLock { state in
            state.sentPackets[packet.packetNumber] = packet
            if packet.inFlight {
                state.bytesInFlight += packet.sentBytes
            }
            if packet.ackEliciting {
                state.ackElicitingInFlight += 1
            }

            // Update smallest unacked
            if state.smallestUnacked == nil || packet.packetNumber < state.smallestUnacked! {
                state.smallestUnacked = packet.packetNumber
            }
        }
    }

    /// Processes acknowledgments and detects losses
    /// - Parameters:
    ///   - ackFrame: The received ACK frame
    ///   - ackReceivedTime: When the ACK was received
    ///   - rttEstimator: The RTT estimator to update
    /// - Returns: Result containing acknowledged and lost packets
    public func onAckReceived(
        ackFrame: AckFrame,
        ackReceivedTime: ContinuousClock.Instant,
        rttEstimator: RTTEstimator
    ) -> LossDetectionResult {
        // Estimate capacity based on ACK ranges to avoid reallocations
        let estimatedAcked = min(
            ackFrame.ackRanges.reduce(0) { $0 + Int($1.rangeLength) + 1 },
            256
        )
        var ackedPackets: [SentPacket] = []
        ackedPackets.reserveCapacity(estimatedAcked)
        var lostPackets: [SentPacket] = []
        lostPackets.reserveCapacity(8)
        var rttSample: Duration? = nil
        var isFirstAckElicitingAck = false

        state.withLock { state in
            let largestAcked = ackFrame.largestAcknowledged

            // Check if this is first acknowledgment
            if state.largestAckedPacket == nil {
                isFirstAckElicitingAck = true
            }

            // Update largest acked
            if state.largestAckedPacket == nil || largestAcked > state.largestAckedPacket! {
                state.largestAckedPacket = largestAcked
            }

            // Process acknowledged packets directly from ACK ranges (no intermediate array)
            processAckedRanges(
                ackFrame: ackFrame,
                state: &state,
                ackedPackets: &ackedPackets,
                rttSample: &rttSample,
                ackReceivedTime: ackReceivedTime
            )

            // Detect lost packets
            lostPackets = detectLostPacketsInternal(
                &state,
                now: ackReceivedTime,
                rttEstimator: rttEstimator
            )
        }

        // Decode ack delay (already in microseconds after frame decoding)
        let ackDelay = Duration.microseconds(Int64(ackFrame.ackDelay))

        return LossDetectionResult(
            ackedPackets: ackedPackets,
            lostPackets: lostPackets,
            rttSample: rttSample,
            ackDelay: ackDelay,
            isFirstAckElicitingAck: isFirstAckElicitingAck
        )
    }

    /// Pre-computed ACK range interval for efficient lookup
    private struct AckInterval {
        let start: UInt64  // Inclusive
        let end: UInt64    // Inclusive
    }

    /// Processes ACK ranges using bounded iteration over sentPackets
    ///
    /// SECURITY: This method iterates over sentPackets.keys (bounded by our own sent packets)
    /// instead of iterating over ACK ranges (which could be attacker-controlled).
    /// This prevents CPU DoS attacks via malicious ACK frames with huge ranges.
    ///
    /// OPTIMIZATION: Pre-computes ACK ranges as intervals once, then uses binary search
    /// for O(packets × log(ranges)) instead of O(packets × ranges).
    @inline(__always)
    private func processAckedRanges(
        ackFrame: AckFrame,
        state: inout LossState,
        ackedPackets: inout [SentPacket],
        rttSample: inout Duration?,
        ackReceivedTime: ContinuousClock.Instant
    ) {
        let largestAcked = ackFrame.largestAcknowledged

        // Pre-compute ACK ranges as intervals (sorted by start descending)
        // This is done once per ACK frame, not per packet
        let intervals = computeAckIntervals(ranges: ackFrame.ackRanges, largestAcked: largestAcked)
        guard !intervals.isEmpty else { return }

        // Build a sorted list of packet numbers to check
        // This is bounded by the number of packets we've sent, not by ACK range sizes
        var packetsToRemove: [UInt64] = []
        packetsToRemove.reserveCapacity(min(state.sentPackets.count, 64))

        for pn in state.sentPackets.keys {
            // Skip packets that can't possibly be acknowledged
            // (packet numbers greater than largest acknowledged)
            guard pn <= largestAcked else { continue }

            // Check if this packet number falls within any ACK range using binary search
            if isPacketInIntervals(pn, intervals: intervals) {
                packetsToRemove.append(pn)
            }
        }

        // Process acknowledged packets
        for pn in packetsToRemove {
            if let packet = state.sentPackets.removeValue(forKey: pn) {
                ackedPackets.append(packet)
                if packet.inFlight {
                    state.bytesInFlight -= packet.sentBytes
                }
                if packet.ackEliciting {
                    state.ackElicitingInFlight -= 1
                }

                // RTT sample from largest newly acked ack-eliciting packet
                if pn == largestAcked && packet.ackEliciting {
                    rttSample = ackReceivedTime - packet.timeSent
                }
            }
        }
    }

    /// Computes ACK intervals from ACK ranges
    ///
    /// ACK ranges are structured as (RFC 9000 Section 19.3.1):
    /// - First range: [largestAcked - firstRange.rangeLength, largestAcked]
    /// - Subsequent ranges: gap indicates unacked packets below (smallest_prev - 1)
    ///
    /// Returns intervals sorted by start (descending order).
    @inline(__always)
    private func computeAckIntervals(ranges: [AckRange], largestAcked: UInt64) -> [AckInterval] {
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
                let gapOffset = range.gap + 1
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

    /// Checks if a packet number falls within any of the pre-computed intervals
    /// using binary search for O(log n) lookup.
    ///
    /// Intervals are sorted by start (descending) and non-overlapping.
    /// Binary search finds the first interval where end >= pn, then we check if start <= pn.
    @inline(__always)
    private func isPacketInIntervals(_ pn: UInt64, intervals: [AckInterval]) -> Bool {
        // Binary search to find the first interval where end >= pn
        // Since intervals are sorted descending (by both start and end),
        // we find the first interval that could contain pn
        var lo = 0
        var hi = intervals.count

        while lo < hi {
            let mid = lo + (hi - lo) / 2
            if intervals[mid].end < pn {
                // This interval's end is below pn, look in earlier (larger) intervals
                hi = mid
            } else {
                // This interval's end >= pn, might contain pn or answer is further right
                lo = mid + 1
            }
        }

        // lo points to one past the last interval where end >= pn
        // Check if the interval at lo-1 contains pn
        if lo > 0 {
            let interval = intervals[lo - 1]
            return pn >= interval.start && pn <= interval.end
        }

        return false
    }

    /// Internal loss detection algorithm (RFC 9002 Section 4.3)
    /// Optimized with single-pass iteration
    private func detectLostPacketsInternal(
        _ state: inout LossState,
        now: ContinuousClock.Instant,
        rttEstimator: RTTEstimator
    ) -> [SentPacket] {
        guard let largestAcked = state.largestAckedPacket else { return [] }

        // Calculate loss delay threshold once
        let baseRTT = max(rttEstimator.latestRTT, rttEstimator.smoothedRTT)
        let lossDelay = baseRTT * LossDetectionConstants.timeThresholdNumerator /
                        LossDetectionConstants.timeThresholdDenominator
        let lossDelayThreshold = max(lossDelay, LossDetectionConstants.granularity)

        var lostPackets: [SentPacket] = []
        lostPackets.reserveCapacity(8)
        var earliestLossTime: ContinuousClock.Instant? = nil
        var newSmallestUnacked: UInt64? = nil
        var packetsToRemove: [UInt64] = []
        packetsToRemove.reserveCapacity(8)

        // Single pass: iterate all packets exactly once
        for (pn, packet) in state.sentPackets {
            if pn >= largestAcked {
                // Packets >= largestAcked: only track for smallest unacked
                if newSmallestUnacked == nil || pn < newSmallestUnacked! {
                    newSmallestUnacked = pn
                }
                continue
            }

            // Packet threshold loss: 3+ newer packets acknowledged
            let packetLost = largestAcked >= pn + LossDetectionConstants.packetThreshold

            // Time threshold loss
            let timeLost = (now - packet.timeSent) >= lossDelayThreshold

            if packetLost || timeLost {
                // Mark for removal (batch delete later)
                packetsToRemove.append(pn)
                lostPackets.append(packet)
                if packet.inFlight {
                    state.bytesInFlight -= packet.sentBytes
                }
                if packet.ackEliciting {
                    state.ackElicitingInFlight -= 1
                }
            } else {
                // Not lost yet - track for loss time and smallest unacked
                if newSmallestUnacked == nil || pn < newSmallestUnacked! {
                    newSmallestUnacked = pn
                }

                // Not yet lost by packet threshold - calculate when it will be lost by time
                if largestAcked < pn + LossDetectionConstants.packetThreshold {
                    let lossTime = packet.timeSent + lossDelayThreshold
                    if earliestLossTime == nil || lossTime < earliestLossTime! {
                        earliestLossTime = lossTime
                    }
                }
            }
        }

        // Batch remove lost packets
        for pn in packetsToRemove {
            state.sentPackets.removeValue(forKey: pn)
        }

        state.lossTime = earliestLossTime
        state.smallestUnacked = newSmallestUnacked

        return lostPackets
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
        state.withLock { state in
            detectLostPacketsInternal(&state, now: now, rttEstimator: rttEstimator)
        }
    }

    /// Gets the earliest loss time for timer scheduling
    public func earliestLossTime() -> ContinuousClock.Instant? {
        state.withLock { $0.lossTime }
    }

    /// Gets packets that need retransmission (ack-eliciting packets still in flight)
    public func getRetransmittablePackets() -> [SentPacket] {
        state.withLock { state in
            // Use lazy filter to avoid intermediate array allocation,
            // then collect only matching packets
            var result: [SentPacket] = []
            result.reserveCapacity(state.ackElicitingInFlight)
            for packet in state.sentPackets.values where packet.ackEliciting {
                result.append(packet)
            }
            return result
        }
    }

    /// Gets the current bytes in flight
    public var bytesInFlight: Int {
        state.withLock { $0.bytesInFlight }
    }

    /// Gets the count of ack-eliciting packets in flight
    public var ackElicitingInFlight: Int {
        state.withLock { $0.ackElicitingInFlight }
    }

    /// Gets the largest acknowledged packet number
    public var largestAckedPacket: UInt64? {
        state.withLock { $0.largestAckedPacket }
    }

    /// Gets the smallest unacked packet number
    public var smallestUnacked: UInt64? {
        state.withLock { $0.smallestUnacked }
    }

    /// Gets the oldest unacknowledged ack-eliciting packets for PTO probing
    ///
    /// RFC 9002 Section 6.2: When PTO expires, send probe packets.
    /// The probe SHOULD carry data from the oldest unacked packet.
    ///
    /// - Parameter count: Maximum number of packets to return (typically 2)
    /// - Returns: Oldest unacked ack-eliciting packets, sorted by packet number
    public func getOldestUnackedPackets(count: Int) -> [SentPacket] {
        state.withLock { state in
            // Get all ack-eliciting packets
            var ackEliciting: [SentPacket] = []
            ackEliciting.reserveCapacity(min(count * 2, state.ackElicitingInFlight))

            for packet in state.sentPackets.values where packet.ackEliciting {
                ackEliciting.append(packet)
            }

            // Sort by packet number (ascending) and take oldest
            ackEliciting.sort { $0.packetNumber < $1.packetNumber }
            return Array(ackEliciting.prefix(count))
        }
    }

    /// Clears state (called when encryption level is discarded)
    public func clear() {
        state.withLock { state in
            state.sentPackets.removeAll()
            state.largestAckedPacket = nil
            state.lossTime = nil
            state.bytesInFlight = 0
            state.ackElicitingInFlight = 0
            state.smallestUnacked = nil
        }
    }
}
