import Testing
@testable import QUICRecoveryCore

@Suite("Recovery core behavior")
struct RecoveryCoreBehaviorTests {
    @Test("server anti-amplification is limited until address validation")
    func antiAmplificationServerLimit() {
        var limiter = AntiAmplificationCore(isServer: true)

        #expect(limiter.isBlocked)
        #expect(!limiter.canSend(bytes: 1))

        limiter.recordBytesReceived(1_200)
        #expect(limiter.availableSendWindow() == 3_600)
        #expect(limiter.canSend(bytes: 3_600))

        limiter.recordBytesSent(3_600)
        #expect(limiter.isBlocked)
        #expect(!limiter.canSend(bytes: 1))

        limiter.validateAddress()
        #expect(!limiter.isBlocked)
        #expect(limiter.availableSendWindow() == UInt64.max)
        #expect(limiter.canSend(bytes: UInt64.max))
    }

    @Test("client anti-amplification is unlimited and accounting saturates")
    func antiAmplificationClientAndSaturation() {
        let client = AntiAmplificationCore(isServer: false)
        #expect(client.canSend(bytes: UInt64.max))
        #expect(client.availableSendWindow() == UInt64.max)

        var server = AntiAmplificationCore(isServer: true)
        server.recordBytesReceived(UInt64.max)
        server.recordBytesReceived(1)
        server.recordBytesSent(UInt64.max)
        server.recordBytesSent(1)
        #expect(server.bytesReceived == UInt64.max)
        #expect(server.bytesSent == UInt64.max)
        #expect(server.sendLimit == UInt64.max)
        #expect(!server.canSend(bytes: 1))
    }

    @Test("RTT estimator applies ACK delay only after confirmation")
    func rttAckDelayContract() {
        var unconfirmed = RTTEstimatorCore()
        unconfirmed.update(
            latestRttNanos: 100_000_000,
            ackDelayNanos: 0,
            maxAckDelayNanos: 25_000_000,
            handshakeConfirmed: false
        )
        unconfirmed.update(
            latestRttNanos: 140_000_000,
            ackDelayNanos: 20_000_000,
            maxAckDelayNanos: 25_000_000,
            handshakeConfirmed: false
        )

        var confirmed = RTTEstimatorCore()
        confirmed.update(
            latestRttNanos: 100_000_000,
            ackDelayNanos: 0,
            maxAckDelayNanos: 25_000_000,
            handshakeConfirmed: false
        )
        confirmed.update(
            latestRttNanos: 140_000_000,
            ackDelayNanos: 20_000_000,
            maxAckDelayNanos: 25_000_000,
            handshakeConfirmed: true
        )

        #expect(unconfirmed.minRTTNanos == 100_000_000)
        #expect(unconfirmed.smoothedRTTNanos == 105_000_000)
        #expect(confirmed.smoothedRTTNanos == 102_500_000)
        #expect(confirmed.rttVarianceNanos == 42_500_000)
        #expect(confirmed.probeTimeoutNanos(maxAckDelayNanos: 25_000_000) == 297_500_000)
    }

    @Test("packet threshold loss only removes locally sent packets")
    func packetThresholdLoss() {
        var detector = LossDetectorCore()
        for packetNumber in UInt64(1)...UInt64(4) {
            detector.onPacketSent(packet(packetNumber, sentAt: 0))
        }

        let result = detector.onAckReceived(
            largestAcked: 4,
            intervals: [AckInterval(start: 4, end: UInt64.max)],
            wasFirstAck: true,
            nowNanos: 1_000_000,
            latestRTTNanos: 100_000_000,
            smoothedRTTNanos: 100_000_000
        )

        #expect(result.acked.map(\.packetNumber) == [4])
        #expect(result.lost.map(\.packetNumber) == [1])
        #expect(result.rttSampleNanos == 1_000_000)
        #expect(result.isFirstAckElicitingAck)
        #expect(detector.bytesInFlight == 2_400)
        #expect(detector.retransmittablePackets().map(\.packetNumber) == [2, 3])
        #expect(detector.smallestUnacked == 2)
        #expect(detector.largestSent == 4)
    }

    @Test("time threshold schedules then reports loss")
    func timeThresholdLoss() {
        var detector = LossDetectorCore()
        detector.onPacketSent(packet(1, sentAt: 0))
        detector.onPacketSent(packet(2, sentAt: 1_000_000))

        let ack = detector.onAckReceived(
            largestAcked: 2,
            intervals: [AckInterval(start: 2, end: 2)],
            wasFirstAck: false,
            nowNanos: 2_000_000,
            latestRTTNanos: 100_000_000,
            smoothedRTTNanos: 100_000_000
        )
        #expect(ack.lost.isEmpty)
        #expect(detector.lossTimeNanos == 112_500_000)

        let loss = detector.detectLostPackets(
            nowNanos: 112_500_000,
            latestRTTNanos: 100_000_000,
            smoothedRTTNanos: 100_000_000
        )
        #expect(loss.lost.map(\.packetNumber) == [1])
        #expect(detector.bytesInFlight == 0)
        #expect(detector.lossTimeNanos == nil)
    }

    @Test("stale non-in-flight packets are pruned without reporting loss")
    func nonInFlightPruning() {
        var detector = LossDetectorCore()
        detector.onPacketSent(
            SentPacketView(
                packetNumber: 1,
                timeSentNanos: 0,
                sentBytes: 50,
                inFlight: false,
                ackEliciting: false
            )
        )
        detector.onPacketSent(packet(4, sentAt: 0))

        let result = detector.onAckReceived(
            largestAcked: 4,
            intervals: [AckInterval(start: 4, end: 4)],
            wasFirstAck: false,
            nowNanos: 1_000_000,
            latestRTTNanos: 100_000_000,
            smoothedRTTNanos: 100_000_000
        )

        #expect(result.lost.isEmpty)
        #expect(result.droppedNonInFlight == [1])
        #expect(detector.bytesInFlight == 0)
    }

    @Test("clear resets every externally observable loss state")
    func clearLossState() {
        var detector = LossDetectorCore()
        detector.onPacketSent(packet(8, sentAt: 10))
        detector.clear()

        #expect(detector.largestAckedPacket == nil)
        #expect(detector.lossTimeNanos == nil)
        #expect(detector.bytesInFlight == 0)
        #expect(detector.ackElicitingInFlight == 0)
        #expect(detector.smallestUnacked == nil)
        #expect(detector.largestSent == nil)
        #expect(detector.retransmittablePackets().isEmpty)
    }

    @Test("pacer distinguishes disabled immediate and insufficient scheduling")
    func pacerScheduling() {
        var disabled = PacerCore(rate: 0, maxBurst: 1_200, nowNanos: 0)
        #expect(disabled.schedule(bytes: UInt64.max, nowNanos: 0) == .disabled)

        var pacer = PacerCore(rate: 1_000, maxBurst: 1_200, nowNanos: 0)
        #expect(pacer.schedule(bytes: 1_000, nowNanos: 0) == .immediate)
        #expect(pacer.currentTokens == 200)
        #expect(pacer.schedule(bytes: 500, nowNanos: 0) == .insufficient(tokensNeeded: 300))
        #expect(pacer.availableTokens(nowNanos: 500_000_000) == 700)
        #expect(pacer.schedule(bytes: 700, nowNanos: 500_000_000) == .immediate)
    }

    @Test("pacer replenishment remains bounded for extreme elapsed time")
    func pacerExtremeElapsedTime() {
        var pacer = PacerCore(rate: UInt64.max, maxBurst: 1_200, nowNanos: 0)
        pacer.consume(bytes: 1_200, nowNanos: 0)
        pacer.setLastUpdate(nanos: 0)

        #expect(pacer.availableTokens(nowNanos: UInt64.max) == 1_200)
    }

    @Test("NewReno grows, reduces once per recovery, and honors the minimum")
    func newRenoTransitions() {
        let rtt = RTTSnapshot(hasEstimate: true, smoothedRTTNanos: 100_000_000)
        let packet = CongestionPacket(sentBytes: 1_200, timeSentNanos: 10, inFlight: true)
        var controller = NewRenoCore()

        #expect(controller.congestionWindow == 12_000)
        #expect(controller.state == .slowStart)
        controller.onPacketsAcknowledged(packets: [packet], rtt: rtt)
        #expect(controller.congestionWindow == 13_200)

        controller.onPacketsLost(packets: [packet], nowNanos: 20, rtt: rtt)
        #expect(controller.congestionWindow == 6_600)
        #expect(controller.state == .recovery(startNanos: 20))
        controller.onPacketsLost(packets: [packet], nowNanos: 30, rtt: rtt)
        #expect(controller.congestionWindow == 6_600)

        controller.onPersistentCongestion()
        #expect(controller.congestionWindow == 2_400)
        #expect(controller.state == .slowStart)
    }

    @Test("CUBIC grows, reduces once per recovery, and honors the minimum")
    func cubicTransitions() {
        let rtt = RTTSnapshot(hasEstimate: true, smoothedRTTNanos: 100_000_000)
        let packet = CongestionPacket(sentBytes: 1_200, timeSentNanos: 10, inFlight: true)
        var controller = CubicCore()

        #expect(controller.clampedWindow == 12_000)
        controller.onPacketsAcknowledged(packets: [packet], nowNanos: 10, rtt: rtt)
        #expect(controller.clampedWindow == 13_200)

        controller.onPacketsLost(packets: [packet], nowNanos: 20, rtt: rtt)
        #expect(controller.clampedWindow == 9_240)
        #expect(controller.state == .recovery(startNanos: 20))
        controller.onPacketsLost(packets: [packet], nowNanos: 30, rtt: rtt)
        #expect(controller.clampedWindow == 9_240)

        controller.onPersistentCongestion()
        #expect(controller.clampedWindow == 2_400)
        #expect(controller.state == .slowStart)
    }

    private func packet(_ packetNumber: UInt64, sentAt: UInt64) -> SentPacketView {
        SentPacketView(
            packetNumber: packetNumber,
            timeSentNanos: sentAt,
            sentBytes: 1_200,
            inFlight: true,
            ackEliciting: true
        )
    }
}
