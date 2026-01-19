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

    /// Processes ACK ranges directly without building intermediate array
    /// Optimized to skip packet numbers below smallestUnacked
    @inline(__always)
    private func processAckedRanges(
        ackFrame: AckFrame,
        state: inout LossState,
        ackedPackets: inout [SentPacket],
        rttSample: inout Duration?,
        ackReceivedTime: ContinuousClock.Instant
    ) {
        let largestAcked = ackFrame.largestAcknowledged
        let smallestUnacked = state.smallestUnacked ?? 0
        var current = largestAcked

        for (index, range) in ackFrame.ackRanges.enumerated() {
            let rangeStart: UInt64
            if index == 0 {
                // Validate: rangeLength must not exceed current to prevent underflow
                guard range.rangeLength <= current else {
                    // Invalid ACK range - skip this range
                    continue
                }
                rangeStart = current - range.rangeLength
            } else {
                // Validate: gap + 2 must not exceed current to prevent underflow
                let gapOffset = range.gap + 2
                guard gapOffset <= current else {
                    // Invalid ACK gap - stop processing
                    break
                }
                current = current - gapOffset
                // Validate: rangeLength must not exceed current
                guard range.rangeLength <= current else {
                    continue
                }
                rangeStart = current - range.rangeLength
            }

            // Skip packet numbers below smallestUnacked (they can't be in sentPackets)
            let checkStart = max(rangeStart, smallestUnacked)

            // Process only packets that might exist in sentPackets
            if checkStart <= current {
                for pn in checkStart...current {
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
            current = rangeStart
        }
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
