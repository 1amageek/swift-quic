/// QUIC Loss Detection (RFC 9002 Section 4)
///
/// Detects lost packets using packet threshold and time threshold criteria.
/// Optimized for efficient ACK processing and loss detection.
///
/// ## Performance Optimizations
/// - Sorted array storage for cache-efficient iteration
/// - Bounds-based filtering to skip irrelevant packets
/// - Binary search for O(log n) packet lookup
/// - Batch operations for reduced overhead

import Foundation
import Synchronization
import QUICCore

/// Loss detection for a single packet number space (RFC 9002)
public final class LossDetector: Sendable {
    private let state: Mutex<LossState>

    private struct LossState {
        /// Sent packets awaiting acknowledgment, stored as sorted array by packet number
        /// Sorted order enables efficient range queries and cache-friendly iteration
        var sentPackets: ContiguousArray<SentPacket>

        /// Index for O(1) packet lookup by packet number
        /// Maps packet number to index in sentPackets array
        var packetIndex: [UInt64: Int]

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

        /// Largest sent packet number (for bounds checking)
        var largestSent: UInt64?

        init() {
            // Pre-allocate capacity to reduce reallocations
            // Typical QUIC connections have <1000 packets in flight
            self.sentPackets = ContiguousArray()
            self.sentPackets.reserveCapacity(128)
            self.packetIndex = Dictionary(minimumCapacity: 128)
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
            let pn = packet.packetNumber

            // Fast path: packets usually arrive in order (append to end)
            if state.sentPackets.isEmpty || pn > state.sentPackets.last!.packetNumber {
                state.packetIndex[pn] = state.sentPackets.count
                state.sentPackets.append(packet)
            } else {
                // Slow path: out-of-order packet (rare in practice)
                // Find insertion point using binary search
                let insertIdx = state.sentPackets.partitioningIndex { $0.packetNumber >= pn }
                state.sentPackets.insert(packet, at: insertIdx)
                // Update indices for all packets after insertion point
                for i in insertIdx..<state.sentPackets.count {
                    state.packetIndex[state.sentPackets[i].packetNumber] = i
                }
            }

            if packet.inFlight {
                state.bytesInFlight += packet.sentBytes
            }
            if packet.ackEliciting {
                state.ackElicitingInFlight += 1
            }

            // Update bounds
            if state.smallestUnacked == nil || pn < state.smallestUnacked! {
                state.smallestUnacked = pn
            }
            if state.largestSent == nil || pn > state.largestSent! {
                state.largestSent = pn
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
    /// SECURITY: This method iterates over sentPackets (bounded by our own sent packets)
    /// instead of iterating over ACK ranges (which could be attacker-controlled).
    /// This prevents CPU DoS attacks via malicious ACK frames with huge ranges.
    ///
    /// OPTIMIZATION:
    /// - Pre-computes ACK ranges as intervals once
    /// - Uses binary search to find packet range bounds
    /// - Iterates only packets within [smallestAcked, largestAcked]
    /// - Batch removal for efficiency
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
        let intervals = computeAckIntervals(ranges: ackFrame.ackRanges, largestAcked: largestAcked)
        guard !intervals.isEmpty else { return }

        // Compute bounds: smallest acknowledged packet number
        let smallestAcked = intervals.last!.start

        // Find the range of indices to check using binary search
        // Only check packets in [smallestAcked, largestAcked]
        let startIdx = state.sentPackets.partitioningIndex { $0.packetNumber >= smallestAcked }
        let endIdx = state.sentPackets.partitioningIndex { $0.packetNumber > largestAcked }

        guard startIdx < endIdx else { return }

        // Collect indices to remove (iterate backwards for stable removal)
        var indicesToRemove: ContiguousArray<Int> = []
        indicesToRemove.reserveCapacity(endIdx - startIdx)

        for i in startIdx..<endIdx {
            let packet = state.sentPackets[i]
            let pn = packet.packetNumber

            // Check if this packet number falls within any ACK range using binary search
            if isPacketInIntervals(pn, intervals: intervals) {
                indicesToRemove.append(i)
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

        // Batch remove in reverse order to maintain index validity
        for i in indicesToRemove.reversed() {
            let pn = state.sentPackets[i].packetNumber
            state.packetIndex.removeValue(forKey: pn)
            state.sentPackets.remove(at: i)
        }

        // Rebuild indices for remaining packets after removal point
        if let firstRemoved = indicesToRemove.first {
            for i in firstRemoved..<state.sentPackets.count {
                state.packetIndex[state.sentPackets[i].packetNumber] = i
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
    /// Optimized with bounded iteration and batch removal
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
        var indicesToRemove: ContiguousArray<Int> = []
        indicesToRemove.reserveCapacity(8)

        // Only iterate packets with pn < largestAcked (potential loss candidates)
        // Use binary search to find the boundary
        let boundaryIdx = state.sentPackets.partitioningIndex { $0.packetNumber >= largestAcked }

        // Process packets before boundary (pn < largestAcked) - potential loss candidates
        for i in 0..<boundaryIdx {
            let packet = state.sentPackets[i]
            let pn = packet.packetNumber

            // Packet threshold loss: 3+ newer packets acknowledged
            let packetLost = largestAcked >= pn + LossDetectionConstants.packetThreshold

            // Time threshold loss
            let timeLost = (now - packet.timeSent) >= lossDelayThreshold

            if packetLost || timeLost {
                indicesToRemove.append(i)
                lostPackets.append(packet)
                if packet.inFlight {
                    state.bytesInFlight -= packet.sentBytes
                }
                if packet.ackEliciting {
                    state.ackElicitingInFlight -= 1
                }
            } else {
                // Not yet lost by packet threshold - calculate when it will be lost by time
                if largestAcked < pn + LossDetectionConstants.packetThreshold {
                    let lossTime = packet.timeSent + lossDelayThreshold
                    if earliestLossTime == nil || lossTime < earliestLossTime! {
                        earliestLossTime = lossTime
                    }
                }
            }
        }

        // Batch remove lost packets in reverse order
        for i in indicesToRemove.reversed() {
            let pn = state.sentPackets[i].packetNumber
            state.packetIndex.removeValue(forKey: pn)
            state.sentPackets.remove(at: i)
        }

        // Rebuild indices after removal
        if !indicesToRemove.isEmpty {
            for i in 0..<state.sentPackets.count {
                state.packetIndex[state.sentPackets[i].packetNumber] = i
            }
        }

        // Update smallest unacked
        state.smallestUnacked = state.sentPackets.first?.packetNumber
        state.lossTime = earliestLossTime

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
            for packet in state.sentPackets where packet.ackEliciting {
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
            // sentPackets is already sorted by packet number
            // Just iterate from the beginning and take first `count` ack-eliciting packets
            var result: [SentPacket] = []
            result.reserveCapacity(count)

            for packet in state.sentPackets {
                if packet.ackEliciting {
                    result.append(packet)
                    if result.count >= count {
                        break
                    }
                }
            }

            return result
        }
    }

    /// Clears state (called when encryption level is discarded)
    public func clear() {
        state.withLock { state in
            state.sentPackets.removeAll(keepingCapacity: true)
            state.packetIndex.removeAll(keepingCapacity: true)
            state.largestAckedPacket = nil
            state.largestSent = nil
            state.lossTime = nil
            state.bytesInFlight = 0
            state.ackElicitingInFlight = 0
            state.smallestUnacked = nil
        }
    }
}

// MARK: - ContiguousArray Extension

extension ContiguousArray {
    /// Returns the index of the first element where the predicate is true
    /// Uses binary search, assumes array is sorted by the predicate
    @inline(__always)
    fileprivate func partitioningIndex(where predicate: (Element) -> Bool) -> Int {
        var low = 0
        var high = count

        while low < high {
            let mid = (low + high) / 2
            if predicate(self[mid]) {
                high = mid
            } else {
                low = mid + 1
            }
        }
        return low
    }
}
