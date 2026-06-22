/// RFC 9000 §14.4 - PMTU Probe Packets Are Not a Congestion Signal
///
/// These tests verify that QUICConnectionHandler routes DPLPMTUD probe outcomes to the
/// PMTU machine (via the registered callback) and, critically, excludes a lost probe from
/// the congestion controller so it is NOT treated as a congestion signal (RFC 9000 §14.4).

import Testing
import Foundation
import Synchronization
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection
@testable import QUICRecovery

@Suite("RFC 9000 §14.4 - PMTU Probe vs Congestion Control")
struct PMTUProbeCongestionRFCTests {

    private func makeHandler() throws -> QUICConnectionHandler {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        var params = TransportParameters()
        params.initialSourceConnectionID = scid
        return QUICConnectionHandler(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            congestionControlAlgorithm: .cubic,
            maxDatagramSize: 1200
        )
    }

    @Test("A lost probe does not reduce the congestion window")
    func lostProbeDoesNotReduceWindow() throws {
        let handler = try makeHandler()
        let initialWindow = handler.congestionWindow
        #expect(initialWindow == 12000)

        // Register packet 0 as a PMTU probe; record packets 0..3 in flight and an ACK-only
        // packet 4 not in flight. Acknowledging packet 4 declares packets 0 and 1 lost.
        handler.registerPMTUProbe(packetNumber: 0)

        let now = ContinuousClock.Instant.now
        for pn: UInt64 in 0..<4 {
            handler.recordSentPacket(SentPacket(
                packetNumber: pn,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            ))
        }
        handler.recordSentPacket(SentPacket(
            packetNumber: 4,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: false,
            inFlight: false,
            sentBytes: 50
        ))

        // Capture probe outcomes reported to the PMTU machine.
        let outcomes = Mutex<[(UInt64, Bool)]>([])
        handler.setPMTUProbeOutcomeCallback { pn, acked in
            outcomes.withLock { $0.append((pn, acked)) }
        }

        let ackFrame = AckFrame(
            largestAcknowledged: 4,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 0)]
        )
        _ = try handler.processFrames([.ack(ackFrame)], level: .application)

        // Packet 1 is a normal lost packet -> CC reduces (CUBIC: 0.7 * 12000 = 8400).
        // Packet 0 is a probe -> excluded from CC, reported as a probe loss instead.
        #expect(handler.congestionWindow == 8400)

        let reported = outcomes.withLock { $0 }
        #expect(reported.contains { $0.0 == 0 && $0.1 == false })
        // The non-probe lost packet (1) is never reported as a probe outcome.
        #expect(!reported.contains { $0.0 == 1 })
    }

    @Test("When ONLY a probe is lost, the window is unchanged")
    func onlyProbeLostKeepsWindow() throws {
        let handler = try makeHandler()
        let initialWindow = handler.congestionWindow

        // Mark every in-flight packet that could be declared lost as a probe.
        handler.registerPMTUProbe(packetNumber: 0)
        handler.registerPMTUProbe(packetNumber: 1)

        let now = ContinuousClock.Instant.now
        for pn: UInt64 in 0..<4 {
            handler.recordSentPacket(SentPacket(
                packetNumber: pn,
                encryptionLevel: .application,
                timeSent: now,
                ackEliciting: true,
                inFlight: true,
                sentBytes: 1200
            ))
        }
        handler.recordSentPacket(SentPacket(
            packetNumber: 4,
            encryptionLevel: .application,
            timeSent: now,
            ackEliciting: false,
            inFlight: false,
            sentBytes: 50
        ))

        let ackFrame = AckFrame(
            largestAcknowledged: 4,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 0)]
        )
        _ = try handler.processFrames([.ack(ackFrame)], level: .application)

        // RFC 9000 §14.4: losing only probe packets is not a congestion signal.
        #expect(handler.congestionWindow == initialWindow)
    }
}
