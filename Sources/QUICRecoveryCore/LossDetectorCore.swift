/// Embedded-clean loss detector (RFC 9002 §6) as a value type.
///
/// This is the byte-identical loss-detection logic of the host `LossDetector`,
/// expressed as a `struct` with `mutating` methods over a sorted array of
/// `SentPacketView`. Time is injected as monotonic `UInt64` nanoseconds; emitted
/// deadlines (`lossTimeNanos`) are returned as `UInt64` nanosecond values. The host
/// adapter holds a `Mutex<LossDetectorCore>`, fixes a `ContinuousClock` epoch,
/// converts `Instant`/`Duration` to nanoseconds, decodes the wire `AckFrame` into
/// `[AckInterval]`, and reconstructs host `SentPacket`s from the returned views — so
/// observable behavior is unchanged.
///
/// ## Algorithm (RFC 9002 §6.1)
/// - Packet threshold (`kPacketThreshold = 3`): a packet is lost when at least
///   3 newer packets have been acknowledged.
/// - Time threshold: a packet is lost when `now - time_sent >= 9/8 * max(srtt, latest)`
///   (floored at `kGranularity`).
///
/// ## Security
/// `onAckReceived` iterates over the locally tracked sent packets (bounded by our own
/// send count), never over the attacker-controlled ACK ranges, preventing CPU-DoS via
/// huge ACK ranges. The adapter pre-decodes ranges into sorted `[AckInterval]`.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.
public struct LossDetectorCore: Sendable {

    // MARK: - Constants

    /// Packet threshold for declaring loss (RFC 9002 §6.1.1: `kPacketThreshold = 3`).
    public static let packetThreshold: UInt64 = 3

    /// Time-threshold numerator (RFC 9002 §6.1.2: `kTimeThreshold = 9/8`).
    public static let timeThresholdNumerator: UInt64 = 9

    /// Time-threshold denominator.
    public static let timeThresholdDenominator: UInt64 = 8

    /// Timer granularity in nanoseconds (RFC 9002 §6.1.2: 1 ms).
    public static let granularityNanos: UInt64 = 1_000_000

    // MARK: - State

    /// Sent packets awaiting acknowledgment, sorted ascending by packet number.
    private var sentPackets: [SentPacketView]

    /// Largest packet number acknowledged so far, or nil.
    public private(set) var largestAckedPacket: UInt64?

    /// Time when the loss timer should fire, in injected monotonic nanoseconds.
    public private(set) var lossTimeNanos: UInt64?

    /// Bytes in flight (counts only in-flight packets).
    public private(set) var bytesInFlight: Int

    /// Ack-eliciting packets in flight.
    public private(set) var ackElicitingInFlight: Int

    /// Smallest unacked packet number (for fast iteration), or nil.
    public private(set) var smallestUnacked: UInt64?

    /// Largest sent packet number (for bounds checking), or nil.
    public private(set) var largestSent: UInt64?

    // MARK: - Initialization

    /// Creates an empty loss detector core.
    public init() {
        self.sentPackets = []
        self.sentPackets.reserveCapacity(128)
        self.largestAckedPacket = nil
        self.lossTimeNanos = nil
        self.bytesInFlight = 0
        self.ackElicitingInFlight = 0
        self.smallestUnacked = nil
        self.largestSent = nil
    }

    // MARK: - Result of processing an ACK

    /// The outcome of `onAckReceived`.
    public struct AckResult: Sendable {
        /// Packets newly acknowledged by this ACK (subset of previously sent).
        public var acked: [SentPacketView]
        /// Packets detected as lost during this ACK processing.
        public var lost: [SentPacketView]
        /// Packet numbers of stale non-in-flight packets removed during loss
        /// detection. These are NOT reported as lost (RFC 9002: loss detection
        /// applies only to in-flight packets) but are removed to bound memory; the
        /// adapter prunes its side table by these numbers.
        public var droppedNonInFlight: [UInt64]
        /// RTT sample in nanoseconds, taken from the largest newly acknowledged
        /// ack-eliciting packet (RFC 9002 §5.1), or nil if not applicable.
        public var rttSampleNanos: UInt64?
        /// Whether the largest newly acknowledged packet was ack-eliciting and this
        /// is the first ACK to acknowledge an ack-eliciting packet.
        public var isFirstAckElicitingAck: Bool

        @inline(__always)
        init() {
            self.acked = []
            self.lost = []
            self.droppedNonInFlight = []
            self.rttSampleNanos = nil
            self.isFirstAckElicitingAck = false
        }
    }

    /// The outcome of a standalone `detectLostPackets` call.
    public struct LossResult: Sendable {
        /// Packets detected as lost.
        public var lost: [SentPacketView]
        /// Packet numbers of stale non-in-flight packets removed (see
        /// `AckResult.droppedNonInFlight`).
        public var droppedNonInFlight: [UInt64]

        @inline(__always)
        init(lost: [SentPacketView], droppedNonInFlight: [UInt64]) {
            self.lost = lost
            self.droppedNonInFlight = droppedNonInFlight
        }
    }

    // MARK: - Recording sends

    /// Records a sent packet (RFC 9002 §6). Fast path is O(1) append for in-order
    /// sends; out-of-order sends fall back to a sorted insert.
    public mutating func onPacketSent(_ packet: SentPacketView) {
        let pn = packet.packetNumber

        if sentPackets.isEmpty || pn > sentPackets[sentPackets.count - 1].packetNumber {
            sentPackets.append(packet)
        } else {
            let insertIdx = partitioningIndex { $0.packetNumber >= pn }
            sentPackets.insert(packet, at: insertIdx)
        }

        if packet.inFlight {
            bytesInFlight += packet.sentBytes
        }
        if packet.ackEliciting {
            ackElicitingInFlight += 1
        }

        if smallestUnacked == nil || pn < smallestUnacked! {
            smallestUnacked = pn
        }
        if largestSent == nil || pn > largestSent! {
            largestSent = pn
        }
    }

    // MARK: - ACK processing

    /// Processes an ACK and detects losses (RFC 9002 §5.1, §6.1).
    ///
    /// - Parameters:
    ///   - largestAcked: The ACK's largest acknowledged packet number.
    ///   - intervals: Acknowledged ranges as inclusive `[start, end]` intervals,
    ///     sorted by `start` descending and non-overlapping (decoded by the adapter
    ///     from the wire `AckFrame`'s gap/rangeLength encoding).
    ///   - wasFirstAck: Whether no ACK had been processed before this one.
    ///   - nowNanos: ACK receive time in monotonic nanoseconds.
    ///   - latestRTTNanos: The RTT estimator's latest RTT in nanoseconds.
    ///   - smoothedRTTNanos: The RTT estimator's smoothed RTT in nanoseconds.
    /// - Returns: Newly acked / lost packets, RTT sample, first-ack flag.
    public mutating func onAckReceived(
        largestAcked: UInt64,
        intervals: [AckInterval],
        wasFirstAck: Bool,
        nowNanos: UInt64,
        latestRTTNanos: UInt64,
        smoothedRTTNanos: UInt64
    ) -> AckResult {
        var result = AckResult()

        processAckedRanges(
            largestAcked: largestAcked,
            intervals: intervals,
            nowNanos: nowNanos,
            result: &result
        )

        // RFC 9002: only update largestAckedPacket AFTER successful ACK processing,
        // so spurious loss detection from invalid ACK frames is avoided.
        if !result.acked.isEmpty {
            if largestAckedPacket == nil || largestAcked > largestAckedPacket! {
                largestAckedPacket = largestAcked
            }
            if wasFirstAck && result.acked.contains(where: { $0.ackEliciting }) {
                result.isFirstAckElicitingAck = true
            }
        }

        let lossResult = detectLostPackets(
            nowNanos: nowNanos,
            latestRTTNanos: latestRTTNanos,
            smoothedRTTNanos: smoothedRTTNanos
        )
        result.lost = lossResult.lost
        result.droppedNonInFlight = lossResult.droppedNonInFlight

        return result
    }

    /// Processes acknowledged ranges via bounded iteration over our sent packets.
    private mutating func processAckedRanges(
        largestAcked: UInt64,
        intervals: [AckInterval],
        nowNanos: UInt64,
        result: inout AckResult
    ) {
        guard !intervals.isEmpty else { return }

        // Smallest acknowledged packet number across all intervals (sorted descending).
        let smallestAcked = intervals[intervals.count - 1].start

        let startIdx = partitioningIndex { $0.packetNumber >= smallestAcked }
        let endIdx = partitioningIndex { $0.packetNumber > largestAcked }
        guard startIdx < endIdx else { return }

        var ackedPacketNumbers = Set<UInt64>()
        ackedPacketNumbers.reserveCapacity(endIdx - startIdx)

        var largestAckedPacketView: SentPacketView? = nil

        for i in startIdx..<endIdx {
            let packet = sentPackets[i]
            let pn = packet.packetNumber

            if isPacketInIntervals(pn, intervals: intervals) {
                ackedPacketNumbers.insert(pn)
                result.acked.append(packet)

                if packet.inFlight {
                    bytesInFlight -= packet.sentBytes
                }
                if packet.ackEliciting {
                    ackElicitingInFlight -= 1
                }

                if pn == largestAcked {
                    largestAckedPacketView = packet
                }
            }
        }

        // RFC 9002 §5.1: RTT sample is generated using ONLY the largest newly
        // acknowledged packet, and only if it is ack-eliciting.
        if let packet = largestAckedPacketView, packet.ackEliciting {
            result.rttSampleNanos = nowNanos >= packet.timeSentNanos
                ? nowNanos - packet.timeSentNanos
                : 0
        }

        if !ackedPacketNumbers.isEmpty {
            sentPackets.removeAll { ackedPacketNumbers.contains($0.packetNumber) }
        }
    }

    /// Detects lost packets (RFC 9002 §6.1) and updates the loss timer.
    public mutating func detectLostPackets(
        nowNanos: UInt64,
        latestRTTNanos: UInt64,
        smoothedRTTNanos: UInt64
    ) -> LossResult {
        guard let largestAcked = largestAckedPacket else {
            return LossResult(lost: [], droppedNonInFlight: [])
        }

        // loss_delay = kTimeThreshold * max(smoothed_rtt, latest_rtt), floored at
        // kGranularity (RFC 9002 §6.1.2).
        let baseRTT = latestRTTNanos > smoothedRTTNanos ? latestRTTNanos : smoothedRTTNanos
        let lossDelay = baseRTT &* Self.timeThresholdNumerator / Self.timeThresholdDenominator
        let lossDelayThreshold = lossDelay > Self.granularityNanos ? lossDelay : Self.granularityNanos

        var lostPackets: [SentPacketView] = []
        lostPackets.reserveCapacity(8)
        var droppedNonInFlight: [UInt64] = []
        var earliestLossTime: UInt64? = nil
        var lostPacketNumbers = Set<UInt64>()
        lostPacketNumbers.reserveCapacity(8)

        // Only iterate packets with pn < largestAcked (potential loss candidates).
        let boundaryIdx = partitioningIndex { $0.packetNumber >= largestAcked }

        for i in 0..<boundaryIdx {
            let packet = sentPackets[i]
            let pn = packet.packetNumber

            let elapsed = nowNanos >= packet.timeSentNanos ? nowNanos - packet.timeSentNanos : 0

            // RFC 9002: loss detection applies only to in-flight packets. Non-in-flight
            // packets (e.g. ACK-only) are still removed once stale to bound memory, but
            // are not reported as lost or counted in the loss timer.
            guard packet.inFlight else {
                let packetLost = largestAcked >= pn &+ Self.packetThreshold
                let timeLost = elapsed >= lossDelayThreshold
                if packetLost || timeLost {
                    lostPacketNumbers.insert(pn)
                    droppedNonInFlight.append(pn)
                    if packet.ackEliciting {
                        ackElicitingInFlight -= 1
                    }
                }
                continue
            }

            let packetLost = largestAcked >= pn &+ Self.packetThreshold
            let timeLost = elapsed >= lossDelayThreshold

            if packetLost || timeLost {
                lostPacketNumbers.insert(pn)
                lostPackets.append(packet)
                bytesInFlight -= packet.sentBytes
                if packet.ackEliciting {
                    ackElicitingInFlight -= 1
                }
            } else {
                // Not yet lost by packet threshold: schedule when it will be lost by
                // time. Only in-flight packets contribute to the loss timer.
                if largestAcked < pn &+ Self.packetThreshold {
                    let lossTime = packet.timeSentNanos &+ lossDelayThreshold
                    if earliestLossTime == nil || lossTime < earliestLossTime! {
                        earliestLossTime = lossTime
                    }
                }
            }
        }

        if !lostPacketNumbers.isEmpty {
            sentPackets.removeAll { lostPacketNumbers.contains($0.packetNumber) }
        }

        smallestUnacked = sentPackets.first?.packetNumber
        lossTimeNanos = earliestLossTime

        return LossResult(lost: lostPackets, droppedNonInFlight: droppedNonInFlight)
    }

    // MARK: - Queries

    /// Ack-eliciting packets still in flight (probe / retransmission candidates).
    public func retransmittablePackets() -> [SentPacketView] {
        var result: [SentPacketView] = []
        result.reserveCapacity(ackElicitingInFlight)
        for packet in sentPackets where packet.ackEliciting {
            result.append(packet)
        }
        return result
    }

    /// The oldest unacked ack-eliciting packets for PTO probing (RFC 9002 §6.2),
    /// up to `count`, sorted by packet number.
    public func oldestUnackedPackets(count: Int) -> [SentPacketView] {
        var result: [SentPacketView] = []
        result.reserveCapacity(count)
        for packet in sentPackets where packet.ackEliciting {
            result.append(packet)
            if result.count >= count { break }
        }
        return result
    }

    /// Clears all state (called when an encryption level is discarded).
    public mutating func clear() {
        sentPackets.removeAll(keepingCapacity: true)
        largestAckedPacket = nil
        largestSent = nil
        lossTimeNanos = nil
        bytesInFlight = 0
        ackElicitingInFlight = 0
        smallestUnacked = nil
    }

    // MARK: - Private helpers

    /// Returns the index of the first element where `predicate` is true, by binary
    /// search over the packet-number-sorted array.
    @inline(__always)
    private func partitioningIndex(where predicate: (SentPacketView) -> Bool) -> Int {
        var low = 0
        var high = sentPackets.count
        while low < high {
            let mid = (low + high) / 2
            if predicate(sentPackets[mid]) {
                high = mid
            } else {
                low = mid + 1
            }
        }
        return low
    }

    /// Checks whether `pn` lies within any interval, by binary search. Intervals are
    /// sorted by start descending and non-overlapping.
    @inline(__always)
    private func isPacketInIntervals(_ pn: UInt64, intervals: [AckInterval]) -> Bool {
        var lo = 0
        var hi = intervals.count
        while lo < hi {
            let mid = lo + (hi - lo) / 2
            if intervals[mid].end < pn {
                hi = mid
            } else {
                lo = mid + 1
            }
        }
        if lo > 0 {
            let interval = intervals[lo - 1]
            return pn >= interval.start && pn <= interval.end
        }
        return false
    }
}
