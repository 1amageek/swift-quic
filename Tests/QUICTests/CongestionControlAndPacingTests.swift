/// Congestion-control selection and outbound pacing tests.
///
/// Verifies that:
/// 1. QUICConfiguration selects the congestion control algorithm (default CUBIC).
/// 2. A connection handler instantiated with each algorithm actually uses it
///    (observed via the distinct multiplicative-decrease factor on loss).
/// 3. Outbound pacing spaces packets at a finite rate, never limits at a zero/disabled
///    rate, and updates the pacing rate from cwnd and smoothed RTT.

import Testing
import Foundation
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection
@testable import QUICRecovery
@testable import QUICTransport

@Suite("Congestion Control Selection Tests")
struct CongestionControlSelectionTests {

    // MARK: - Configuration

    @Test("Default congestion control algorithm is CUBIC")
    func defaultAlgorithmIsCubic() {
        let config = QUICConfiguration()
        #expect(config.congestionControlAlgorithm == .cubic)
        #expect(config.pacingEnabled == true)
    }

    @Test("Congestion control algorithm is configurable")
    func algorithmIsConfigurable() {
        var config = QUICConfiguration()
        config.congestionControlAlgorithm = .newReno
        #expect(config.congestionControlAlgorithm == .newReno)
    }

    @Test("Factory produces the requested controller type")
    func factoryProducesType() {
        let cubic = CongestionControlAlgorithm.cubic.makeController(maxDatagramSize: 1200)
        let reno = CongestionControlAlgorithm.newReno.makeController(maxDatagramSize: 1200)
        #expect(cubic is CubicCongestionController)
        #expect(reno is NewRenoCongestionController)
    }

    // MARK: - Connection uses the selected controller

    /// Drives a packet-threshold loss through a handler and returns the resulting
    /// congestion window. With kPacketThreshold = 3, acknowledging packet 4 while
    /// packets 0..4 are in flight declares packets 0 and 1 lost, triggering the
    /// controller's multiplicative decrease.
    private func windowAfterLoss(
        algorithm: CongestionControlAlgorithm
    ) throws -> Int {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)

        let handler = QUICConnectionHandler(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            congestionControlAlgorithm: algorithm,
            maxDatagramSize: 1200
        )

        let initialWindow = handler.congestionWindow
        #expect(initialWindow == 12000)

        // Record packets 0..3 as in-flight ack-eliciting application packets, and
        // packet 4 as a non-in-flight ACK-only packet. Acknowledging packet 4 then
        // declares packets 0 and 1 lost (packet threshold) WITHOUT growing the window
        // (non-in-flight ACKs do not increase cwnd), isolating the loss reduction.
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

        // Acknowledge only packet 4. ackRange covers [4, 4]; packets 0 and 1 fall
        // below the packet threshold and are declared lost.
        let ackFrame = AckFrame(
            largestAcknowledged: 4,
            ackDelay: 0,
            ackRanges: [AckRange(gap: 0, rangeLength: 0)]
        )
        _ = try handler.processFrames([.ack(ackFrame)], level: .application)

        return handler.congestionWindow
    }

    @Test("Connection with CUBIC reduces window by beta_cubic (0.7) on loss")
    func cubicReductionOnLoss() throws {
        let window = try windowAfterLoss(algorithm: .cubic)
        // CUBIC: cwnd = 0.7 * 12000 = 8400.
        #expect(window == 8400)
    }

    @Test("Connection with NewReno reduces window by 0.5 on loss")
    func newRenoReductionOnLoss() throws {
        let window = try windowAfterLoss(algorithm: .newReno)
        // NewReno: cwnd = 0.5 * 12000 = 6000.
        #expect(window == 6000)
    }

    @Test("CUBIC and NewReno produce different windows on the same loss")
    func algorithmsDiffer() throws {
        let cubic = try windowAfterLoss(algorithm: .cubic)
        let reno = try windowAfterLoss(algorithm: .newReno)
        #expect(cubic != reno)
        #expect(cubic > reno)  // CUBIC's milder decrease leaves a larger window.
    }
}

@Suite("Outbound Pacing Tests")
struct OutboundPacingTests {

    private func makeConnection(pacingEnabled: Bool) throws -> ManagedConnection {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        return ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address,
            congestionControlAlgorithm: .cubic,
            pacingEnabled: pacingEnabled
        )
    }

    // MARK: - Disabled / zero rate = no limiting

    @Test("Pacing disabled: send path is never delayed")
    func pacingDisabledNoLimiting() throws {
        let connection = try makeConnection(pacingEnabled: false)
        // No delay regardless of packet size or how many packets are queried.
        for _ in 0..<100 {
            #expect(connection.pacingDelay(bytes: 1200) == nil)
        }
        #expect(connection.isPacingActive == false)
        #expect(connection.pacingRate == 0)
    }

    @Test("Pacing enabled but no RTT estimate: zero rate, no limiting")
    func pacingEnabledNoRTTNoLimiting() throws {
        let connection = try makeConnection(pacingEnabled: true)
        // Until an RTT estimate exists the pacer stays disabled (rate 0 = no limit).
        for _ in 0..<100 {
            #expect(connection.pacingDelay(bytes: 1200) == nil)
        }
        #expect(connection.isPacingActive == false)
        #expect(connection.pacingRate == 0)
    }

    // MARK: - Finite-rate spacing (token bucket)

    @Test("Finite rate does not release a full cwnd instantly")
    func finiteRateSpacesPackets() {
        // Drive the token-bucket pacer directly with a finite rate to model the send
        // path: a finite rate must NOT allow an unbounded burst. Once the bucket is
        // drained, subsequent packets are delayed.
        let pacer = Pacer(config: PacingConfiguration(
            initialRate: 1_200_000,        // 1.2 MB/s
            maxBurst: 1200 * 5,            // allow a 5-packet burst
            minInterval: .zero
        ))

        var immediate = 0
        var delayed = 0
        // Attempt to send 20 packets of 1200 bytes back-to-back.
        for _ in 0..<20 {
            if pacer.packetDelay(bytes: 1200) == nil {
                immediate += 1
            } else {
                delayed += 1
            }
        }

        // The burst is bounded: not all 20 packets are released immediately.
        #expect(immediate <= 6)        // ~5-packet burst (plus possible tiny replenish)
        #expect(immediate >= 1)
        #expect(delayed > 0)           // remaining packets are paced (delayed)
        #expect(immediate + delayed == 20)
    }

    @Test("Pacing delay reflects the configured rate")
    func pacingDelayReflectsRate() {
        // With a known rate and an empty bucket, the delay for one packet is
        // approximately bytes / rate.
        let pacer = Pacer(config: PacingConfiguration(
            initialRate: 1_200_000,  // 1.2 MB/s => 1200 bytes takes ~1ms
            maxBurst: 1200,          // one packet of burst
            minInterval: .zero
        ))

        // Consume the single burst packet immediately.
        #expect(pacer.packetDelay(bytes: 1200) == nil)

        // The next packet must wait: delay ~ 1200 / 1_200_000 s = 1ms.
        let delay = pacer.packetDelay(bytes: 1200)
        #expect(delay != nil)
        if let delay {
            let ms = Double(delay.components.seconds) * 1000
                + Double(delay.components.attoseconds) / 1e15
            // Allow generous tolerance; the point is a positive, bounded delay.
            #expect(ms > 0.1)
            #expect(ms < 100)
        }
    }

    // MARK: - Rate update from cwnd / srtt (RFC 9002 §7.7)

    @Test("Pacing rate updates from congestion window and smoothed RTT")
    func pacingRateUpdatesFromCongestion() {
        // RFC 9002 §7.7: rate = N * cwnd / srtt, N = 1.25.
        let pacer = Pacer(config: .disabled)
        #expect(pacer.rate == 0)

        // cwnd = 12000 bytes, srtt = 100ms => rate = 1.25 * 12000 / 0.1 = 150000 B/s.
        pacer.updateFromCongestion(
            congestionWindow: 12000,
            smoothedRTT: .milliseconds(100),
            pacingGain: 1.25
        )
        #expect(pacer.rate == 150_000)
        #expect(pacer.isEnabled == true)

        // A larger window raises the rate proportionally.
        pacer.updateFromCongestion(
            congestionWindow: 24000,
            smoothedRTT: .milliseconds(100),
            pacingGain: 1.25
        )
        #expect(pacer.rate == 300_000)

        // A larger RTT lowers the rate.
        pacer.updateFromCongestion(
            congestionWindow: 24000,
            smoothedRTT: .milliseconds(200),
            pacingGain: 1.25
        )
        #expect(pacer.rate == 150_000)
    }

    // MARK: - Pacer overflow regression (SIGTRAP fix)

    @Test("Pacer does not trap on a large elapsed with an extreme rate")
    func pacerExtremeRateLargeElapsedDoesNotTrap() {
        // Reproduces the token-bucket replenish overflow: a huge pacing rate
        // (e.g. cwnd/srtt with a tiny RTT) combined with a non-trivial elapsed
        // made `UInt64(elapsedSeconds * rate)` overflow and SIGTRAP.
        let pacer = Pacer(config: PacingConfiguration(
            initialRate: UInt64.max / 2,
            maxBurst: 12_000,
            minInterval: .microseconds(1)
        ))
        pacer.consume(bytes: 12_000)                       // drain → headroom > 0
        pacer._setLastUpdateForTesting(secondsInPast: 1_000_000_000)  // 1e9 s elapsed
        // Must not trap, and tokens must stay clamped to maxBurst.
        _ = pacer.packetDelay(bytes: 1_200)
        #expect(pacer.currentTokens <= 12_000)
        pacer.consume(bytes: 1_200)                        // also exercises consume's replenish
        #expect(pacer.currentTokens <= 12_000)
    }

    @Test("Pacer with zero rate never limits (no divide-by-zero)")
    func pacerZeroRateNoLimit() {
        let pacer = Pacer(config: PacingConfiguration(
            initialRate: 0, maxBurst: 12_000, minInterval: .milliseconds(1)
        ))
        #expect(pacer.packetDelay(bytes: 1_200) == nil)
    }
}
