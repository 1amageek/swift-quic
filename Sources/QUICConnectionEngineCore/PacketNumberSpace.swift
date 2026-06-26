// PacketNumberSpace.swift
// One of the three QUIC packet-number spaces (RFC 9000 §12.3): Initial,
// Handshake, Application. Each owns its own send/receive numbering, loss
// detector, and the received-packet bookkeeping the engine needs to generate
// ACK frames. Value type, clock-free (time injected as `nowNanos`).

import QUICWire
import QUICRecoveryCore

/// Per-space state the engine keeps for one encryption level.
///
/// The 0-RTT and 1-RTT levels share the Application space (RFC 9000 §12.3), so
/// the engine maps both onto a single ``PacketNumberSpace``.
struct PacketNumberSpace: Sendable {
    /// The next packet number to assign for an outbound packet in this space.
    var nextPacketNumber: UInt64 = 0

    /// The largest packet number received in this space (for PN decoding).
    var largestReceived: UInt64?
    /// Receive time for the current largest acknowledged packet, used to encode
    /// ACK Delay as time since that packet arrived (RFC 9000 §19.3).
    var largestReceivedTimeNanos: UInt64?

    /// The loss detector for this space (sorted-array threshold detection).
    var lossDetector: LossDetectorCore = LossDetectorCore()

    // MARK: - ACK generation bookkeeping (RFC 9000 §13.2)

    /// Received packet numbers awaiting acknowledgement, kept as sorted,
    /// non-overlapping inclusive `[start, end]` intervals (descending by start).
    var ackRanges: [AckInterval] = []

    /// Whether an ack-eliciting packet has been received since the last ACK we
    /// sent (gates whether we owe an ACK at all, RFC 9000 §13.2.1).
    var ackElicitingPending: Bool = false

    /// The monotonic time the first as-yet-unacknowledged ack-eliciting packet
    /// was received, used to honor `max_ack_delay` (RFC 9000 §13.2.1). `nil`
    /// when nothing is pending.
    var ackDeadlineNanos: UInt64?

    /// The largest packet number we have already acknowledged to the peer, so we
    /// avoid re-sending ACKs that carry no new information.
    var largestAcked: UInt64?

    /// Whether any ACK has been processed in this space (for first-ACK RTT logic).
    var hasReceivedAck: Bool = false

    /// Whether this space has been discarded (RFC 9001 §4.9: Initial/Handshake
    /// keys are dropped after the handshake). A discarded space sends/receives
    /// nothing further.
    var isDiscarded: Bool = false

    init() {}

    // MARK: - Outbound numbering

    /// Returns the next packet number and advances the counter, refusing to wrap
    /// past 2^62 - 1 (RFC 9000 §12.3 — exhaustion MUST close the connection).
    mutating func takeNextPacketNumber() throws(QUICEngineError) -> UInt64 {
        let pn = nextPacketNumber
        guard pn < (1 << 62) else { throw .packetNumberExhausted(.initial) }
        nextPacketNumber = pn &+ 1
        return pn
    }

    // MARK: - Inbound recording (ACK range maintenance)

    /// Records a received packet number, merging it into the sorted ACK-range
    /// set, and tracks whether an ACK is owed.
    mutating func recordReceived(packetNumber pn: UInt64, ackEliciting: Bool, nowNanos: UInt64) {
        if let largest = largestReceived {
            if pn > largest {
                largestReceived = pn
                largestReceivedTimeNanos = nowNanos
            }
        } else {
            largestReceived = pn
            largestReceivedTimeNanos = nowNanos
        }

        insertIntoAckRanges(pn)

        if ackEliciting {
            if !ackElicitingPending {
                ackDeadlineNanos = nowNanos
            }
            ackElicitingPending = true
        }
    }

    /// Whether an ACK frame would convey new information to the peer.
    var hasNewAckInformation: Bool {
        guard let largest = largestReceived else { return false }
        if let lastAcked = largestAcked { return largest > lastAcked }
        return true
    }

    /// Builds the wire ACK frame for the currently-tracked ranges (RFC 9000
    /// §19.3), encoding the gap/length form from the descending intervals.
    /// `ackDelayWireUnits` is the measured delay already scaled by the local ACK
    /// delay exponent. Returns `nil` if nothing is acknowledgeable.
    func makeAckFrame(ackDelayWireUnits: UInt64) -> AckFrame? {
        guard !ackRanges.isEmpty else { return nil }
        // ackRanges is sorted descending by start; the first interval contains
        // the largest acknowledged.
        let largest = ackRanges[0].end
        var ranges: [AckRange] = []
        // First range length: end - start of the top interval.
        let firstLen = ackRanges[0].end - ackRanges[0].start
        ranges.append(AckRange(gap: 0, rangeLength: firstLen))
        var previousStart = ackRanges[0].start
        for i in 1..<ackRanges.count {
            let interval = ackRanges[i]
            // Gap = number of unacked packets between previousStart-1 and
            // interval.end, encoded as gap = (previousStart - 1) - interval.end - 1.
            let gap = previousStart - interval.end - 2
            let len = interval.end - interval.start
            ranges.append(AckRange(gap: gap, rangeLength: len))
            previousStart = interval.start
        }
        return AckFrame(largestAcknowledged: largest, ackDelay: ackDelayWireUnits, ackRanges: ranges, ecnCounts: nil)
    }

    /// Marks the current ranges as acknowledged to the peer and clears the
    /// ack-eliciting pending state (called after an ACK has been queued).
    mutating func onAckSent() {
        largestAcked = largestReceived
        ackElicitingPending = false
        ackDeadlineNanos = nil
    }

    // MARK: - Private

    private mutating func insertIntoAckRanges(_ pn: UInt64) {
        // Maintain descending-by-start, non-overlapping, coalesced intervals.
        if ackRanges.isEmpty {
            ackRanges = [AckInterval(start: pn, end: pn)]
            return
        }
        // Find insertion / coalesce position.
        var i = 0
        while i < ackRanges.count {
            let interval = ackRanges[i]
            if pn > interval.end {
                // pn sits before (higher than) this interval.
                if pn == interval.end + 1 {
                    // Extend upward.
                    ackRanges[i] = AckInterval(start: interval.start, end: pn)
                    coalesceUpward(at: i)
                } else {
                    ackRanges.insert(AckInterval(start: pn, end: pn), at: i)
                }
                return
            } else if pn >= interval.start && pn <= interval.end {
                // Already covered.
                return
            } else if pn == interval.start - 1 {
                // Extend downward.
                ackRanges[i] = AckInterval(start: pn, end: interval.end)
                coalesceDownward(at: i)
                return
            }
            i += 1
        }
        // pn is lower than all existing intervals.
        ackRanges.append(AckInterval(start: pn, end: pn))
    }

    private mutating func coalesceUpward(at index: Int) {
        // After extending interval[index].end upward, it may touch interval[index-1].
        guard index > 0 else { return }
        let upper = ackRanges[index - 1]
        let current = ackRanges[index]
        if current.end + 1 >= upper.start {
            ackRanges[index - 1] = AckInterval(start: current.start, end: max(upper.end, current.end))
            ackRanges.remove(at: index)
        }
    }

    private mutating func coalesceDownward(at index: Int) {
        // After extending interval[index].start downward, it may touch interval[index+1].
        guard index + 1 < ackRanges.count else { return }
        let lower = ackRanges[index + 1]
        let current = ackRanges[index]
        if lower.end + 1 >= current.start {
            ackRanges[index] = AckInterval(start: min(lower.start, current.start), end: current.end)
            ackRanges.remove(at: index + 1)
        }
    }
}
