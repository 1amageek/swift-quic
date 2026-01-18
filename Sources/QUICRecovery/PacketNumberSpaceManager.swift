/// Packet Number Space Manager
///
/// Coordinates loss detection and ACK management across all encryption levels.

import Foundation
import Synchronization
import QUICCore

/// Manages loss detection and ACK state for all packet number spaces
public final class PacketNumberSpaceManager: Sendable {
    /// Loss detectors per encryption level (packet number space)
    public let lossDetectors: [EncryptionLevel: LossDetector]

    /// ACK managers per encryption level
    public let ackManagers: [EncryptionLevel: AckManager]

    /// RTT estimator (shared across all spaces)
    private let _rttEstimator: Mutex<RTTEstimator>

    /// PTO count (consecutive probe timeouts)
    private let _ptoCount: Mutex<Int>

    /// Whether handshake is confirmed
    private let _handshakeConfirmed: Mutex<Bool>

    /// Creates a new PacketNumberSpaceManager
    /// - Parameter maxAckDelay: Maximum ACK delay for ACK generation
    public init(maxAckDelay: Duration = LossDetectionConstants.defaultMaxAckDelay) {
        var detectors: [EncryptionLevel: LossDetector] = [:]
        var acks: [EncryptionLevel: AckManager] = [:]

        // Create managers for each packet number space
        // Note: Initial and 0-RTT share the same packet number space in loss detection
        // but we track them separately for simplicity
        for level in [EncryptionLevel.initial, .handshake, .application] {
            detectors[level] = LossDetector()
            acks[level] = AckManager(maxAckDelay: maxAckDelay)
        }

        self.lossDetectors = detectors
        self.ackManagers = acks
        self._rttEstimator = Mutex(RTTEstimator())
        self._ptoCount = Mutex(0)
        self._handshakeConfirmed = Mutex(false)
    }

    /// Gets the current RTT estimator state
    public var rttEstimator: RTTEstimator {
        _rttEstimator.withLock { $0 }
    }

    /// Gets the current PTO count
    public var ptoCount: Int {
        _ptoCount.withLock { $0 }
    }

    /// Whether handshake is confirmed
    public var handshakeConfirmed: Bool {
        get { _handshakeConfirmed.withLock { $0 } }
        set { _handshakeConfirmed.withLock { $0 = newValue } }
    }

    /// Updates RTT from a new sample
    /// - Parameters:
    ///   - sample: The RTT sample
    ///   - ackDelay: The ack delay reported by peer
    ///   - maxAckDelay: The peer's max_ack_delay transport parameter
    public func updateRTT(
        sample: Duration,
        ackDelay: Duration,
        maxAckDelay: Duration
    ) {
        let confirmed = handshakeConfirmed
        _rttEstimator.withLock { estimator in
            estimator.updateRTT(
                rttSample: sample,
                ackDelay: ackDelay,
                maxAckDelay: maxAckDelay,
                handshakeConfirmed: confirmed
            )
        }
    }

    /// Discards an encryption level (called after handshake completion)
    /// - Parameter level: The encryption level to discard
    public func discardLevel(_ level: EncryptionLevel) {
        lossDetectors[level]?.clear()
        ackManagers[level]?.clear()
    }

    /// Calculates the next PTO deadline
    /// - Parameters:
    ///   - now: Current time
    ///   - maxAckDelay: The peer's max_ack_delay
    /// - Returns: The PTO deadline
    public func nextPTODeadline(
        now: ContinuousClock.Instant,
        maxAckDelay: Duration
    ) -> ContinuousClock.Instant {
        let confirmed = handshakeConfirmed
        let effectiveMaxAckDelay = confirmed ? maxAckDelay : .zero

        let pto = _rttEstimator.withLock { rtt in
            rtt.probeTimeout(maxAckDelay: effectiveMaxAckDelay)
        }

        let ptoMultiplier = _ptoCount.withLock { 1 << $0 }  // 2^pto_count
        return now + (pto * ptoMultiplier)
    }

    /// Increments PTO count on timeout
    public func onPTOExpired() {
        _ptoCount.withLock { $0 += 1 }
    }

    /// Resets PTO count on successful ACK
    public func resetPTOCount() {
        _ptoCount.withLock { $0 = 0 }
    }

    /// Gets the earliest loss time across all levels
    /// - Returns: The earliest loss time, or nil if none
    public func earliestLossTime() -> (level: EncryptionLevel, time: ContinuousClock.Instant)? {
        var earliest: (level: EncryptionLevel, time: ContinuousClock.Instant)? = nil

        for level in [EncryptionLevel.initial, .handshake, .application] {
            if let lossTime = lossDetectors[level]?.earliestLossTime() {
                if earliest == nil || lossTime < earliest!.time {
                    earliest = (level, lossTime)
                }
            }
        }

        return earliest
    }

    /// Gets the earliest ACK time across all levels
    /// - Returns: The earliest ACK time, or nil if none
    public func earliestAckTime() -> (level: EncryptionLevel, time: ContinuousClock.Instant)? {
        var earliest: (level: EncryptionLevel, time: ContinuousClock.Instant)? = nil

        for level in [EncryptionLevel.initial, .handshake, .application] {
            if let ackTime = ackManagers[level]?.nextAckTime() {
                if earliest == nil || ackTime < earliest!.time {
                    earliest = (level, ackTime)
                }
            }
        }

        return earliest
    }

    /// Whether any level has ack-eliciting packets in flight
    public var hasAckElicitingInFlight: Bool {
        for level in [EncryptionLevel.initial, .handshake, .application] {
            if let detector = lossDetectors[level], detector.ackElicitingInFlight > 0 {
                return true
            }
        }
        return false
    }

    /// Total bytes in flight across all levels
    public var totalBytesInFlight: Int {
        var total = 0
        for level in [EncryptionLevel.initial, .handshake, .application] {
            total += lossDetectors[level]?.bytesInFlight ?? 0
        }
        return total
    }

    /// Records a sent packet
    /// - Parameter packet: The sent packet
    public func onPacketSent(_ packet: SentPacket) {
        lossDetectors[packet.encryptionLevel]?.onPacketSent(packet)
    }

    /// Records a received packet
    /// - Parameters:
    ///   - packetNumber: The packet number
    ///   - level: The encryption level
    ///   - isAckEliciting: Whether the packet is ack-eliciting
    ///   - receiveTime: When the packet was received
    public func onPacketReceived(
        packetNumber: UInt64,
        level: EncryptionLevel,
        isAckEliciting: Bool,
        receiveTime: ContinuousClock.Instant
    ) {
        ackManagers[level]?.recordReceivedPacket(
            packetNumber: packetNumber,
            isAckEliciting: isAckEliciting,
            receiveTime: receiveTime
        )
    }

    /// Processes an ACK frame
    /// - Parameters:
    ///   - ackFrame: The received ACK frame
    ///   - level: The encryption level
    ///   - receiveTime: When the ACK was received
    ///   - maxAckDelay: The peer's max_ack_delay
    /// - Returns: The loss detection result
    public func onAckReceived(
        ackFrame: AckFrame,
        level: EncryptionLevel,
        receiveTime: ContinuousClock.Instant,
        maxAckDelay: Duration
    ) -> LossDetectionResult {
        guard let lossDetector = lossDetectors[level] else {
            return .empty
        }

        let rtt = rttEstimator
        let result = lossDetector.onAckReceived(
            ackFrame: ackFrame,
            ackReceivedTime: receiveTime,
            rttEstimator: rtt
        )

        // Update RTT if we got a sample
        if let sample = result.rttSample {
            updateRTT(
                sample: sample,
                ackDelay: result.ackDelay,
                maxAckDelay: maxAckDelay
            )
        }

        // Reset PTO count on valid ACK
        if !result.ackedPackets.isEmpty {
            resetPTOCount()
        }

        return result
    }

    /// Generates an ACK frame for a level if needed
    /// - Parameters:
    ///   - level: The encryption level
    ///   - now: Current time
    ///   - ackDelayExponent: The ACK delay exponent
    /// - Returns: An ACK frame, or nil if not needed
    public func generateAckFrame(
        for level: EncryptionLevel,
        now: ContinuousClock.Instant,
        ackDelayExponent: UInt64
    ) -> AckFrame? {
        ackManagers[level]?.generateAckFrame(now: now, ackDelayExponent: ackDelayExponent)
    }
}
