/// CUBIC Congestion Controller Unit Tests
///
/// Deterministic tests for the CUBIC congestion control implementation (RFC 9438).
/// All tests drive onPacketSent/onPacketsAcknowledged/onPacketsLost directly with
/// explicit timestamps, so behavior is fully reproducible without timing.

import Testing
import Foundation
@testable import QUICRecovery
@testable import QUICCore

@Suite("CUBIC Congestion Controller Tests")
struct CubicCongestionControllerTests {

    // MARK: - Helpers

    private func makeRTT(_ sample: Duration = .milliseconds(50)) -> RTTEstimator {
        var rtt = RTTEstimator()
        rtt.updateRTT(
            rttSample: sample,
            ackDelay: .zero,
            maxAckDelay: .milliseconds(25),
            handshakeConfirmed: true
        )
        return rtt
    }

    private func packet(
        _ pn: UInt64,
        timeSent: ContinuousClock.Instant,
        bytes: Int = 1200,
        ackEliciting: Bool = true,
        inFlight: Bool = true
    ) -> SentPacket {
        SentPacket(
            packetNumber: pn,
            encryptionLevel: .application,
            timeSent: timeSent,
            ackEliciting: ackEliciting,
            inFlight: inFlight,
            sentBytes: bytes
        )
    }

    // MARK: - Initialization

    @Test("Initial window matches RFC 9002 §7.2")
    func initialWindow() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        // min(10 * 1200, max(14720, 2400)) = min(12000, 14720) = 12000
        #expect(cc.congestionWindow == 12000)
        #expect(cc.currentState == .slowStart)
    }

    @Test("Available window calculation")
    func availableWindow() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        #expect(cc.availableWindow(bytesInFlight: 0) == 12000)
        #expect(cc.availableWindow(bytesInFlight: 5000) == 7000)
        #expect(cc.availableWindow(bytesInFlight: 12000) == 0)
        #expect(cc.availableWindow(bytesInFlight: 20000) == 0)
    }

    // MARK: - Slow Start

    @Test("Slow start grows exponentially (cwnd += bytes_acked)")
    func slowStartGrowth() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()
        let initial = cc.congestionWindow

        let p = packet(0, timeSent: now)
        cc.onPacketSent(bytes: p.sentBytes, now: now)
        cc.onPacketsAcknowledged(packets: [p], now: now + .milliseconds(50), rtt: rtt)

        #expect(cc.congestionWindow == initial + 1200)
        #expect(cc.currentState == .slowStart)
    }

    @Test("Slow start with multiple packets")
    func slowStartMultiple() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()
        let initial = cc.congestionWindow

        var packets: [SentPacket] = []
        for i: UInt64 in 0..<5 {
            let p = packet(i, timeSent: now)
            packets.append(p)
            cc.onPacketSent(bytes: p.sentBytes, now: now)
        }
        cc.onPacketsAcknowledged(packets: packets, now: now + .milliseconds(50), rtt: rtt)

        #expect(cc.congestionWindow == initial + 6000)
    }

    // MARK: - Loss / Multiplicative Decrease (beta = 0.7)

    @Test("Loss multiplicatively decreases window by beta_cubic (0.7)")
    func lossMultiplicativeDecrease() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()
        let initial = cc.congestionWindow  // 12000

        let p = packet(0, timeSent: now)
        cc.onPacketSent(bytes: p.sentBytes, now: now)
        cc.onPacketsLost(packets: [p], now: now + .milliseconds(100), rtt: rtt)

        // RFC 9438 §4.6: cwnd = beta_cubic * cwnd = 0.7 * 12000 = 8400
        #expect(cc.congestionWindow == Int((Double(initial) * 0.7).rounded()))
        #expect(cc.congestionWindow == 8400)
    }

    @Test("Loss records W_max and enters recovery")
    func lossRecordsWMaxAndRecovery() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()

        let p = packet(0, timeSent: now)
        cc.onPacketSent(bytes: p.sentBytes, now: now)
        let lossTime = now + .milliseconds(100)
        cc.onPacketsLost(packets: [p], now: lossTime, rtt: rtt)

        // Recovery state recorded with the loss time.
        if case .recovery(let start) = cc.currentState {
            #expect(start == lossTime)
        } else {
            #expect(Bool(false), "Expected recovery state after loss")
        }

        // W_max recorded at the pre-loss window (12000); the cubic curve will aim
        // back toward it. The description exposes wMax for verification.
        #expect(cc.description.contains("wMax=12000"))
    }

    @Test("Only one window reduction per recovery period")
    func oneReductionPerRTT() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()

        var packets: [SentPacket] = []
        for i: UInt64 in 0..<5 {
            let p = packet(i, timeSent: now)
            packets.append(p)
            cc.onPacketSent(bytes: p.sentBytes, now: now)
        }

        cc.onPacketsLost(packets: [packets[0]], now: now + .milliseconds(100), rtt: rtt)
        let after = cc.congestionWindow

        cc.onPacketsLost(packets: [packets[1]], now: now + .milliseconds(105), rtt: rtt)
        #expect(cc.congestionWindow == after)

        cc.onPacketsLost(packets: [packets[2]], now: now + .milliseconds(110), rtt: rtt)
        #expect(cc.congestionWindow == after)
    }

    // MARK: - Congestion Avoidance (Cubic Curve)

    @Test("Congestion avoidance follows the cubic curve toward W_max")
    func cubicCurveGrowth() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let baseNow = ContinuousClock.Instant.now
        let rtt = makeRTT(.milliseconds(50))

        // Trigger a loss to set W_max = 12000 and enter congestion avoidance.
        let lossPacket = packet(0, timeSent: baseNow)
        cc.onPacketSent(bytes: lossPacket.sentBytes, now: baseNow)
        let recoveryStart = baseNow + .milliseconds(100)
        cc.onPacketsLost(packets: [lossPacket], now: recoveryStart, rtt: rtt)

        let windowAfterLoss = cc.congestionWindow  // 8400

        // Exit recovery with a post-recovery ACK.
        let exitPacket = packet(1, timeSent: recoveryStart + .milliseconds(10))
        cc.onPacketSent(bytes: exitPacket.sentBytes, now: exitPacket.timeSent)
        cc.onPacketsAcknowledged(
            packets: [exitPacket],
            now: recoveryStart + .milliseconds(60),
            rtt: rtt
        )
        #expect(cc.currentState == .congestionAvoidance)

        // Drive congestion-avoidance ACKs over increasing elapsed time. The window
        // must grow (concave region) but stay below the initial W_max early on, then
        // approach it as t -> K. We verify monotonic non-decreasing growth and that
        // it climbs back above the post-loss window.
        var pn: UInt64 = 2
        var previous = cc.congestionWindow
        var elapsedMs: Int64 = 100
        for _ in 0..<40 {
            let sentAt = recoveryStart + .milliseconds(elapsedMs)
            let p = packet(pn, timeSent: sentAt)
            cc.onPacketSent(bytes: p.sentBytes, now: sentAt)
            cc.onPacketsAcknowledged(
                packets: [p],
                now: sentAt + .milliseconds(1),
                rtt: rtt
            )
            let current = cc.congestionWindow
            // Cubic growth in congestion avoidance is monotonic non-decreasing.
            #expect(current >= previous)
            previous = current
            pn += 1
            elapsedMs += 100
        }

        // The window recovered above the reduced (post-loss) window via the curve.
        #expect(cc.congestionWindow > windowAfterLoss)
    }

    @Test("TCP-friendly region: CUBIC not slower than Reno")
    func tcpFriendlyNotSlowerThanReno() {
        // Drive identical loss + congestion-avoidance ACK sequences through CUBIC and
        // NewReno over the same short-RTT timeline. CUBIC's Reno-friendly estimate
        // guarantees its window is never below NewReno's.
        let cubic = CubicCongestionController(maxDatagramSize: 1200)
        let reno = NewRenoCongestionController(maxDatagramSize: 1200)
        let baseNow = ContinuousClock.Instant.now
        let rtt = makeRTT(.milliseconds(20))

        func driveLossThenCA(_ cc: any CongestionController) {
            let lossPacket = packet(0, timeSent: baseNow)
            cc.onPacketSent(bytes: lossPacket.sentBytes, now: baseNow)
            let recoveryStart = baseNow + .milliseconds(50)
            cc.onPacketsLost(packets: [lossPacket], now: recoveryStart, rtt: rtt)

            // Exit recovery.
            let exit = packet(1, timeSent: recoveryStart + .milliseconds(5))
            cc.onPacketSent(bytes: exit.sentBytes, now: exit.timeSent)
            cc.onPacketsAcknowledged(
                packets: [exit],
                now: recoveryStart + .milliseconds(30),
                rtt: rtt
            )

            // Many congestion-avoidance ACKs.
            var pn: UInt64 = 2
            var elapsedMs: Int64 = 60
            for _ in 0..<200 {
                let sentAt = recoveryStart + .milliseconds(elapsedMs)
                let p = packet(pn, timeSent: sentAt)
                cc.onPacketSent(bytes: p.sentBytes, now: sentAt)
                cc.onPacketsAcknowledged(
                    packets: [p],
                    now: sentAt + .milliseconds(1),
                    rtt: rtt
                )
                pn += 1
                elapsedMs += 20
            }
        }

        driveLossThenCA(cubic)
        driveLossThenCA(reno)

        // CUBIC must be at least as aggressive as Reno (Reno-friendly region).
        #expect(cubic.congestionWindow >= reno.congestionWindow)
    }

    // MARK: - Recovery Exit

    @Test("Recovery exit on post-recovery ACK")
    func recoveryExit() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()

        let pre = packet(0, timeSent: now)
        cc.onPacketSent(bytes: pre.sentBytes, now: now)
        let lossTime = now + .milliseconds(100)
        cc.onPacketsLost(packets: [pre], now: lossTime, rtt: rtt)
        #expect(cc.currentState == .recovery(startTime: lossTime))

        // ACK of a pre-recovery packet should NOT exit recovery.
        let pre2 = packet(1, timeSent: now + .milliseconds(50))
        cc.onPacketSent(bytes: pre2.sentBytes, now: pre2.timeSent)
        cc.onPacketsAcknowledged(packets: [pre2], now: lossTime + .milliseconds(50), rtt: rtt)
        #expect(cc.currentState == .recovery(startTime: lossTime))

        // ACK of a post-recovery packet exits recovery.
        let post = packet(2, timeSent: lossTime + .milliseconds(10))
        cc.onPacketSent(bytes: post.sentBytes, now: post.timeSent)
        cc.onPacketsAcknowledged(packets: [post], now: lossTime + .milliseconds(60), rtt: rtt)
        #expect(cc.currentState == .congestionAvoidance)
    }

    // MARK: - Minimum Window

    @Test("Window never drops below minimum (2 * max_datagram_size)")
    func minimumWindowRespected() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()

        for i in 0..<15 {
            let sentAt = now + .milliseconds(Int64(i) * 300)
            let p = packet(UInt64(i), timeSent: sentAt)
            cc.onPacketSent(bytes: p.sentBytes, now: sentAt)
            cc.onPacketsLost(packets: [p], now: sentAt + .milliseconds(100), rtt: rtt)

            // Exit recovery so the next loss reduces again.
            let exit = packet(UInt64(1000 + i), timeSent: sentAt + .milliseconds(150))
            cc.onPacketSent(bytes: exit.sentBytes, now: exit.timeSent)
            cc.onPacketsAcknowledged(
                packets: [exit],
                now: exit.timeSent + .milliseconds(50),
                rtt: rtt
            )
        }

        #expect(cc.congestionWindow >= 2 * 1200)
    }

    // MARK: - ECN

    @Test("ECN triggers the same multiplicative decrease as loss")
    func ecnReduction() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let initial = cc.congestionWindow

        cc.onECNCongestionEvent(now: now)

        #expect(cc.congestionWindow == Int((Double(initial) * 0.7).rounded()))
        #expect(cc.currentState == .recovery(startTime: now))
    }

    // MARK: - Persistent Congestion

    @Test("Persistent congestion collapses window and re-enters slow start")
    func persistentCongestion() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()

        for i: UInt64 in 0..<10 {
            let p = packet(i, timeSent: now)
            cc.onPacketSent(bytes: p.sentBytes, now: now)
            cc.onPacketsAcknowledged(packets: [p], now: now + .milliseconds(50), rtt: rtt)
        }
        let before = cc.congestionWindow

        cc.onPersistentCongestion()

        #expect(cc.congestionWindow == 2 * 1200)
        #expect(cc.congestionWindow < before)
        #expect(cc.currentState == .slowStart)
    }

    // MARK: - Non-in-flight

    @Test("Non-in-flight packets do not affect the window")
    func nonInFlight() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT()
        let initial = cc.congestionWindow

        let ackOnly = packet(0, timeSent: now, bytes: 50, ackEliciting: false, inFlight: false)
        cc.onPacketSent(bytes: ackOnly.sentBytes, now: now)
        cc.onPacketsAcknowledged(packets: [ackOnly], now: now + .milliseconds(50), rtt: rtt)

        #expect(cc.congestionWindow == initial)
    }

    // MARK: - Pacing

    @Test("Initial burst tokens allow immediate sending")
    func initialBurst() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        #expect(cc.nextSendTime() == nil)
    }

    @Test("Pacing rate established after RTT sample")
    func pacingRateEstablished() {
        let cc = CubicCongestionController(maxDatagramSize: 1200)
        let now = ContinuousClock.Instant.now
        let rtt = makeRTT(.milliseconds(100))

        // Exhaust burst tokens.
        for _ in 0..<10 {
            cc.onPacketSent(bytes: 1200, now: now)
        }

        let p = packet(0, timeSent: now)
        cc.onPacketsAcknowledged(packets: [p], now: now + .milliseconds(100), rtt: rtt)

        // After consuming burst and establishing a rate, the next send is scheduled.
        cc.onPacketSent(bytes: 1200, now: now + .milliseconds(100))
        let next = cc.nextSendTime()
        #expect(next != nil)
        if let next {
            #expect(next > now + .milliseconds(100))
        }
    }
}
