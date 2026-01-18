/// Congestion Controller Unit Tests
///
/// Comprehensive tests for NewReno congestion control implementation (RFC 9002 Section 7).

import Testing
import Foundation
@testable import QUICRecovery
@testable import QUICCore

@Suite("NewReno Congestion Controller Tests")
struct NewRenoCongestionControllerTests {

    // MARK: - Initialization Tests

    @Test("Initial window is correctly calculated")
    func initialWindow() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)

        // RFC 9002: initial_window = min(10 * max_datagram_size, max(14720, 2 * max_datagram_size))
        // = min(10 * 1200, max(14720, 2400)) = min(12000, 14720) = 12000
        #expect(cc.congestionWindow == 12000)
        #expect(cc.currentState == .slowStart)
    }

    @Test("Initial window with small max datagram size")
    func initialWindowSmallMDS() {
        // With small max_datagram_size (e.g., 500)
        // initial_window = min(5000, max(14720, 1000)) = min(5000, 14720) = 5000
        let cc = NewRenoCongestionController(maxDatagramSize: 500)
        #expect(cc.congestionWindow == 5000)
    }

    @Test("Initial window with large max datagram size")
    func initialWindowLargeMDS() {
        // With large max_datagram_size (e.g., 1500)
        // initial_window = min(15000, max(14720, 3000)) = min(15000, 14720) = 14720
        let cc = NewRenoCongestionController(maxDatagramSize: 1500)
        #expect(cc.congestionWindow == 14720)
    }

    // MARK: - Available Window Tests

    @Test("Available window calculation")
    func availableWindowCalculation() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)

        // Initial: cwnd = 12000
        #expect(cc.availableWindow(bytesInFlight: 0) == 12000)
        #expect(cc.availableWindow(bytesInFlight: 5000) == 7000)
        #expect(cc.availableWindow(bytesInFlight: 12000) == 0)
        #expect(cc.availableWindow(bytesInFlight: 15000) == 0)  // clamped to 0
    }

    // MARK: - Slow Start Tests

    @Test("Slow start exponential growth")
    func slowStartExponentialGrowth() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        let initialWindow = cc.congestionWindow

        // Send and ACK a packet
        let packet = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: packet.sentBytes, now: now)
        cc.onPacketsAcknowledged(packets: [packet], now: now + .milliseconds(50), rtt: rtt)

        // Slow start: cwnd += bytes_acked
        #expect(cc.congestionWindow == initialWindow + 1200)
        #expect(cc.currentState == .slowStart)
    }

    @Test("Slow start with multiple packets")
    func slowStartMultiplePackets() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        let initialWindow = cc.congestionWindow

        // Send and ACK 5 packets
        var packets: [SentPacket] = []
        for i: UInt64 in 0..<5 {
            let packet = SentPacket(
                packetNumber: i,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            packets.append(packet)
            cc.onPacketSent(bytes: packet.sentBytes, now: now)
        }

        cc.onPacketsAcknowledged(packets: packets, now: now + .milliseconds(50), rtt: rtt)

        // Slow start: cwnd += 5 * 1200 = 6000
        #expect(cc.congestionWindow == initialWindow + 6000)
    }

    // MARK: - Congestion Avoidance Tests

    @Test("Transition to congestion avoidance")
    func transitionToCongestionAvoidance() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Force into congestion avoidance by triggering loss first
        let lossPacket = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: lossPacket.sentBytes, now: now)
        cc.onPacketsLost(packets: [lossPacket], now: now + .milliseconds(100), rtt: rtt)

        // After loss: cwnd = max(cwnd/2, minimum_window)
        // ssthresh is set, so we're now in congestion avoidance
        #expect(cc.currentState == .recovery(startTime: now + .milliseconds(100)))

        // After recovery ends with a post-recovery ACK, we'll be in congestion avoidance
    }

    @Test("Congestion avoidance linear growth")
    func congestionAvoidanceLinearGrowth() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Trigger loss to set ssthresh and enter recovery
        let lossPacket = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: lossPacket.sentBytes, now: now)
        cc.onPacketsLost(packets: [lossPacket], now: now + .milliseconds(100), rtt: rtt)

        let recoveryStart = now + .milliseconds(100)
        let windowAfterLoss = cc.congestionWindow  // 6000 (12000 / 2)

        // Send and ACK a post-recovery packet to exit recovery
        let recoveryPacket = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: recoveryStart + .milliseconds(10),  // After recovery started
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: recoveryPacket.sentBytes, now: recoveryPacket.timeSent)
        cc.onPacketsAcknowledged(packets: [recoveryPacket], now: recoveryStart + .milliseconds(60), rtt: rtt)

        // Should have exited recovery and be in congestion avoidance
        #expect(cc.currentState == .congestionAvoidance)

        // In congestion avoidance, we need to ACK cwnd worth of bytes to increase by max_datagram_size
        let windowBeforeCA = cc.congestionWindow

        // ACK more packets until we accumulate enough bytes
        var totalAcked = 1200  // Already acked recoveryPacket
        var pn: UInt64 = 2
        while totalAcked < windowBeforeCA {
            let packet = SentPacket(
                packetNumber: pn,
                encryptionLevel: .application,
                timeSent: recoveryStart + .milliseconds(20),
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            cc.onPacketSent(bytes: packet.sentBytes, now: packet.timeSent)
            cc.onPacketsAcknowledged(packets: [packet], now: recoveryStart + .milliseconds(70), rtt: rtt)
            totalAcked += 1200
            pn += 1
        }

        // After acking cwnd bytes, window should increase by max_datagram_size
        #expect(cc.congestionWindow >= windowBeforeCA + 1200)
    }

    // MARK: - Loss Detection Tests

    @Test("Loss triggers window reduction")
    func lossTriggersWindowReduction() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        let initialWindow = cc.congestionWindow  // 12000

        let packet = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: packet.sentBytes, now: now)
        cc.onPacketsLost(packets: [packet], now: now + .milliseconds(100), rtt: rtt)

        // RFC 9002: cwnd = max(cwnd * loss_reduction_factor, minimum_window)
        // = max(12000 * 0.5, 2400) = max(6000, 2400) = 6000
        #expect(cc.congestionWindow == initialWindow / 2)
    }

    @Test("Loss sets ssthresh correctly")
    func lossSetsSSThresh() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        let packet = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: packet.sentBytes, now: now)
        cc.onPacketsLost(packets: [packet], now: now + .milliseconds(100), rtt: rtt)

        // After recovery, acking a new packet should show we're in congestion avoidance
        // (cwnd >= ssthresh)
        let postRecoveryPacket = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: now + .milliseconds(110),
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: postRecoveryPacket.sentBytes, now: postRecoveryPacket.timeSent)
        cc.onPacketsAcknowledged(packets: [postRecoveryPacket], now: now + .milliseconds(160), rtt: rtt)

        #expect(cc.currentState == .congestionAvoidance)
    }

    @Test("Only one window reduction per RTT")
    func onlyOneReductionPerRTT() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Send multiple packets
        var packets: [SentPacket] = []
        for i: UInt64 in 0..<5 {
            let packet = SentPacket(
                packetNumber: i,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            packets.append(packet)
            cc.onPacketSent(bytes: packet.sentBytes, now: now)
        }

        // First loss
        cc.onPacketsLost(packets: [packets[0]], now: now + .milliseconds(100), rtt: rtt)
        let windowAfterFirstLoss = cc.congestionWindow

        // Second loss in same recovery period - should NOT reduce window again
        cc.onPacketsLost(packets: [packets[1]], now: now + .milliseconds(105), rtt: rtt)
        #expect(cc.congestionWindow == windowAfterFirstLoss)

        // Third loss - still in recovery
        cc.onPacketsLost(packets: [packets[2]], now: now + .milliseconds(110), rtt: rtt)
        #expect(cc.congestionWindow == windowAfterFirstLoss)
    }

    // MARK: - Recovery Tests

    @Test("Recovery state tracking")
    func recoveryStateTracking() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        #expect(cc.currentState == .slowStart)

        let packet = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: packet.sentBytes, now: now)

        let lossTime = now + .milliseconds(100)
        cc.onPacketsLost(packets: [packet], now: lossTime, rtt: rtt)

        if case .recovery(let startTime) = cc.currentState {
            #expect(startTime == lossTime)
        } else {
            #expect(Bool(false), "Expected recovery state")
        }
    }

    @Test("Recovery exit on post-recovery ACK")
    func recoveryExitOnPostRecoveryAck() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Send pre-recovery packet
        let preRecoveryPacket = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: preRecoveryPacket.sentBytes, now: now)

        let lossTime = now + .milliseconds(100)
        cc.onPacketsLost(packets: [preRecoveryPacket], now: lossTime, rtt: rtt)

        // We're in recovery now
        #expect(cc.currentState == .recovery(startTime: lossTime))

        // ACK of a pre-recovery packet should NOT exit recovery
        // (But this packet was already lost, so we need another pre-recovery packet)
        let preRecoveryPacket2 = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: now + .milliseconds(50),  // Before recovery start
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: preRecoveryPacket2.sentBytes, now: preRecoveryPacket2.timeSent)
        cc.onPacketsAcknowledged(packets: [preRecoveryPacket2], now: lossTime + .milliseconds(50), rtt: rtt)

        // Still in recovery (packet was sent before recovery)
        #expect(cc.currentState == .recovery(startTime: lossTime))

        // Send and ACK a post-recovery packet
        let postRecoveryPacket = SentPacket(
            packetNumber: 2,
            encryptionLevel: .application,
            timeSent: lossTime + .milliseconds(10),  // After recovery start
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketSent(bytes: postRecoveryPacket.sentBytes, now: postRecoveryPacket.timeSent)
        cc.onPacketsAcknowledged(packets: [postRecoveryPacket], now: lossTime + .milliseconds(60), rtt: rtt)

        // Should have exited recovery
        #expect(cc.currentState == .congestionAvoidance)
    }

    // MARK: - Persistent Congestion Tests

    @Test("Persistent congestion collapses window")
    func persistentCongestionCollapsesWindow() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // First, grow the window
        for i: UInt64 in 0..<10 {
            let packet = SentPacket(
                packetNumber: i,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            cc.onPacketSent(bytes: packet.sentBytes, now: now)
            cc.onPacketsAcknowledged(packets: [packet], now: now + .milliseconds(50), rtt: rtt)
        }

        let windowBeforePersistentCongestion = cc.congestionWindow

        // Trigger persistent congestion
        cc.onPersistentCongestion()

        // RFC 9002: Window collapses to minimum_window = 2 * max_datagram_size
        #expect(cc.congestionWindow == 2 * 1200)
        #expect(cc.congestionWindow < windowBeforePersistentCongestion)

        // Should be back in slow start
        #expect(cc.currentState == .slowStart)
    }

    // MARK: - ECN Tests

    @Test("ECN triggers same reduction as loss")
    func ecnTriggersReduction() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now

        let initialWindow = cc.congestionWindow

        cc.onECNCongestionEvent(now: now)

        // Same as loss: cwnd reduced by half
        #expect(cc.congestionWindow == initialWindow / 2)
        #expect(cc.currentState == .recovery(startTime: now))
    }

    @Test("ECN respects recovery period")
    func ecnRespectsRecoveryPeriod() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now

        // First ECN event
        cc.onECNCongestionEvent(now: now)
        let windowAfterFirstECN = cc.congestionWindow

        // Second ECN event during recovery - should not reduce again
        cc.onECNCongestionEvent(now: now + .milliseconds(10))
        #expect(cc.congestionWindow == windowAfterFirstECN)
    }

    // MARK: - Pacing Tests

    @Test("Initial burst tokens allow immediate sending")
    func initialBurstTokens() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)

        // Initially, burst tokens should allow immediate sending
        #expect(cc.nextSendTime() == nil)
    }

    @Test("Burst tokens are consumed on send")
    func burstTokensConsumed() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now

        // Send 10 packets (initial burst tokens)
        for _ in 0..<10 {
            cc.onPacketSent(bytes: 1200, now: now)
        }

        // After burst tokens exhausted, need RTT estimate for pacing
        // If no RTT estimate, still allows immediate sending
        #expect(cc.nextSendTime() == nil)
    }

    @Test("Pacing rate established after RTT sample")
    func pacingRateEstablished() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(100), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Consume burst tokens
        for _ in 0..<10 {
            cc.onPacketSent(bytes: 1200, now: now)
        }

        // ACK a packet to update pacing rate
        let packet = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )
        cc.onPacketsAcknowledged(packets: [packet], now: now + .milliseconds(100), rtt: rtt)

        // After sending another packet, next send time should be set
        cc.onPacketSent(bytes: 1200, now: now + .milliseconds(100))

        let nextTime = cc.nextSendTime()
        #expect(nextTime != nil)
        if let nextTime = nextTime {
            #expect(nextTime > now + .milliseconds(100))
        }
    }

    // MARK: - Non-in-flight Packets Tests

    @Test("Non-in-flight packets don't affect congestion window")
    func nonInFlightPackets() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        let initialWindow = cc.congestionWindow

        // ACK-only packets are not in-flight
        let ackOnlyPacket = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: false,
            inFlight: false,
            sentBytes: 50
        )
        cc.onPacketSent(bytes: ackOnlyPacket.sentBytes, now: now)
        cc.onPacketsAcknowledged(packets: [ackOnlyPacket], now: now + .milliseconds(50), rtt: rtt)

        // Window should not change for non-in-flight packets
        #expect(cc.congestionWindow == initialWindow)
    }

    // MARK: - Minimum Window Tests

    @Test("Window never goes below minimum")
    func windowNeverBelowMinimum() {
        let cc = NewRenoCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        var rtt = RTTEstimator()
        rtt.updateRTT(rttSample: .milliseconds(50), ackDelay: .zero, maxAckDelay: .milliseconds(25), handshakeConfirmed: true)

        // Trigger multiple losses to reduce window
        for i in 0..<10 {
            let packet = SentPacket(
                packetNumber: UInt64(i),
                encryptionLevel: .application,
                timeSent: now + .milliseconds(i * 200),
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            cc.onPacketSent(bytes: packet.sentBytes, now: packet.timeSent)
            cc.onPacketsLost(packets: [packet], now: packet.timeSent + .milliseconds(100), rtt: rtt)

            // Exit recovery with a post-recovery ACK
            let recoveryExitPacket = SentPacket(
                packetNumber: UInt64(1000 + i),
                encryptionLevel: .application,
                timeSent: packet.timeSent + .milliseconds(150),
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            )
            cc.onPacketSent(bytes: recoveryExitPacket.sentBytes, now: recoveryExitPacket.timeSent)
            cc.onPacketsAcknowledged(packets: [recoveryExitPacket], now: recoveryExitPacket.timeSent + .milliseconds(50), rtt: rtt)
        }

        // Window should never go below minimum (2 * max_datagram_size)
        #expect(cc.congestionWindow >= 2 * 1200)
    }
}

// MARK: - PacketNumberSpaceManager Persistent Congestion Tests

@Suite("Persistent Congestion Detection Tests")
struct PersistentCongestionDetectionTests {

    @Test("Persistent congestion requires at least 2 packets")
    func requiresAtLeast2Packets() {
        let manager = PacketNumberSpaceManager()
        manager.peerMaxAckDelay = .milliseconds(25)
        let now = ContinuousClock.Instant.now

        let singlePacket = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let result = manager.checkPersistentCongestion(lostPackets: [singlePacket])

        #expect(result == false)
    }

    @Test("Persistent congestion requires ack-eliciting packets")
    func requiresAckElicitingPackets() {
        let manager = PacketNumberSpaceManager()
        manager.peerMaxAckDelay = .milliseconds(25)
        let now = ContinuousClock.Instant.now

        // Non-ack-eliciting packets
        let packets = (0..<5).map { i in
            SentPacket(
                packetNumber: UInt64(i),
                encryptionLevel: .application,
                timeSent: now + .seconds(i),
                ackEliciting: false,
                inFlight: false,
                sentBytes: 50
            )
        }

        let result = manager.checkPersistentCongestion(lostPackets: packets)

        #expect(result == false)
    }

    @Test("Persistent congestion detection with sufficient time span")
    func detectsPersistentCongestion() {
        let manager = PacketNumberSpaceManager()
        manager.peerMaxAckDelay = .milliseconds(25)
        let now = ContinuousClock.Instant.now

        // PTO = smoothed_rtt + max(4*rttvar, 1ms) + max_ack_delay
        // Initial: smoothed_rtt = 333ms, rttvar = 166.5ms
        // But before handshake confirmed, effectiveMaxAckDelay = 0
        // PTO = 333 + max(666, 1) + 0 = 999ms
        // Congestion period = 2 * PTO * 3 = 2 * 999 * 3 ≈ 6000ms

        // Create packets with time span > 6 seconds
        let packet1 = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let packet2 = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: now + .seconds(10),  // 10 seconds later (> 6s)
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let result = manager.checkPersistentCongestion(lostPackets: [packet1, packet2])

        #expect(result == true)
    }

    @Test("No persistent congestion with short time span")
    func noPersistentCongestionShortSpan() {
        let manager = PacketNumberSpaceManager()
        manager.peerMaxAckDelay = .milliseconds(25)
        let now = ContinuousClock.Instant.now

        // Create packets with time span < congestion period
        let packet1 = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let packet2 = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: now + .milliseconds(500),  // 500ms (< 6s)
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let result = manager.checkPersistentCongestion(lostPackets: [packet1, packet2])

        #expect(result == false)
    }

    @Test("Persistent congestion uses peerMaxAckDelay after handshake confirmed")
    func persistentCongestionUsesPerMaxAckDelay() {
        let manager = PacketNumberSpaceManager()
        manager.peerMaxAckDelay = .milliseconds(100)  // Large value
        manager.handshakeConfirmed = true  // Enable peerMaxAckDelay usage
        let now = ContinuousClock.Instant.now

        // With handshake confirmed and peerMaxAckDelay = 100ms:
        // PTO = 333 + max(666, 1) + 100 = 1099ms
        // Congestion period = 2 * 1099 * 3 ≈ 6594ms

        // Create packets with time span that would pass without peerMaxAckDelay
        // but fail with it
        let packet1 = SentPacket(
            packetNumber: 0,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        let packet2 = SentPacket(
            packetNumber: 1,
            encryptionLevel: .application,
            timeSent: now + .milliseconds(6200),  // Just over 6s but under 6.6s
            ackEliciting: true,
            inFlight: true,
            sentBytes: 1200
        )

        // Without handshake confirmed, this would be persistent congestion
        // With handshake confirmed and larger peerMaxAckDelay, it should NOT be
        let result = manager.checkPersistentCongestion(lostPackets: [packet1, packet2])

        #expect(result == false)
    }
}
