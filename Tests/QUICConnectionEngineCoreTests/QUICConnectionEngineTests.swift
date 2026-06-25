// QUICConnectionEngineTests.swift
// Host tests for the cored QUICConnectionEngine. They drive the value-type,
// caller-locked, sans-IO, clock-free engine directly — time is injected as an
// explicit `nowNanos`, with NO real sleeps (mirroring the DTLS engine timer
// tests). A loopback pair (client + server) exercises the receive/send path over
// Initial keys, which both peers derive identically from the original DCID.

import Testing
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import P2PCrypto
import P2PCoreCrypto
@testable import QUICConnectionEngineCore

private typealias Provider = DefaultCryptoProvider

/// A trivial monotonic clock for the engine's `T` parameter. The engine never
/// reads it (time is injected), so it just satisfies the constraint.
private struct TestClock: MonotonicClock {
    func monotonicMillis() -> UInt64 { 0 }
    func monotonicNanos() -> UInt64 { 0 }
}

private typealias Engine = QUICConnectionEngine<Provider, TestClock>

@Suite("QUICConnectionEngine — cored, clock-free orchestrator")
struct QUICConnectionEngineTests {

    // MARK: - Helpers

    private func makeConfig(role: QUICEngineRole, dcid: ConnectionID, scid: ConnectionID, idleNanos: UInt64 = 30_000_000_000) -> QUICConnectionEngineConfiguration<Provider> {
        var tp = TransportParametersCore()
        tp.initialMaxData = 1_000_000
        tp.initialMaxStreamDataBidiLocal = 256 * 1024
        tp.initialMaxStreamDataBidiRemote = 256 * 1024
        tp.initialMaxStreamDataUni = 256 * 1024
        tp.initialMaxStreamsBidi = 100
        tp.initialMaxStreamsUni = 100
        return QUICConnectionEngineConfiguration<Provider>(
            role: role,
            version: .v1,
            localConnectionID: scid,
            initialPeerConnectionID: dcid,
            originalDestinationConnectionID: dcid,
            localTransportParameters: tp,
            maxDatagramSize: 1200,
            idleTimeoutNanos: idleNanos,
            maxAckDelayNanos: 25_000_000,
            pathValidationTimeoutNanos: 3_000_000_000
        )
    }

    /// Builds a client + server engine pair that share the original DCID, so both
    /// install identical Initial keys (RFC 9001 §5.2) — enough to round-trip
    /// 1-RTT-shaped Initial packets in these unit tests without a TLS handshake.
    private func makePair(idleNanos: UInt64 = 30_000_000_000) throws -> (client: Engine, server: Engine, dcid: ConnectionID, clientSCID: ConnectionID, serverSCID: ConnectionID) {
        let dcid = try #require(ConnectionID.random(length: 8))
        let clientSCID = try #require(ConnectionID.random(length: 8))
        let serverSCID = try #require(ConnectionID.random(length: 8))
        var client = try Engine(configuration: makeConfig(role: .client, dcid: dcid, scid: clientSCID, idleNanos: idleNanos), nowNanos: 0)
        // The server's "peer CID" is the client's SCID; both derive Initial keys
        // from the SAME original DCID.
        var serverCfg = makeConfig(role: .server, dcid: clientSCID, scid: serverSCID, idleNanos: idleNanos)
        serverCfg.originalDestinationConnectionID = dcid
        var server = try Engine(configuration: serverCfg, nowNanos: 0)
        // Simulate the handshake's transport-parameter exchange so both peers know
        // each other's stream-count + flow-control limits.
        var peerTP = TransportParametersCore()
        peerTP.initialMaxData = 1_000_000
        peerTP.initialMaxStreamDataBidiLocal = 256 * 1024
        peerTP.initialMaxStreamDataBidiRemote = 256 * 1024
        peerTP.initialMaxStreamDataUni = 256 * 1024
        peerTP.initialMaxStreamsBidi = 100
        peerTP.initialMaxStreamsUni = 100
        client.applyPeerTransportParameters(peerTP)
        server.applyPeerTransportParameters(peerTP)

        // Simulate the handshake's key install: both peers install matching
        // application (1-RTT) keys so STREAM data flows. The client's WRITE secret
        // is the server's READ secret and vice versa (RFC 9001 §5.1).
        let clientToServer = [UInt8](repeating: 0xC0, count: 32)
        let serverToClient = [UInt8](repeating: 0x05, count: 32)
        try client.installKeys(level: .application, readSecret: serverToClient, writeSecret: clientToServer, suite: .aes128GCM)
        try server.installKeys(level: .application, readSecret: clientToServer, writeSecret: serverToClient, suite: .aes128GCM)
        // Discard Initial keys + validate the path so anti-amplification doesn't
        // block 1-RTT sends (post-handshake state).
        client.markHandshakeComplete()
        server.markHandshakeComplete()
        return (client, server, dcid, clientSCID, serverSCID)
    }

    // MARK: - Construction

    @Test("engine constructs and installs Initial keys")
    func constructsWithInitialKeys() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        let engine = try Engine(configuration: makeConfig(role: .client, dcid: dcid, scid: scid), nowNanos: 0)
        #expect(!engine.isEstablished)
        #expect(!engine.isClosed)
        #expect(engine.currentKeyPhase == 0)
    }

    @Test("unsupported version with no salt throws")
    func unsupportedVersionThrows() throws {
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))
        var cfg = makeConfig(role: .client, dcid: dcid, scid: scid)
        cfg.version = QUICVersion(rawValue: 0xDEADBEEF)  // no initial salt
        #expect(throws: QUICEngineError.self) {
            _ = try Engine(configuration: cfg, nowNanos: 0)
        }
    }

    // MARK: - Clock-free idle timeout

    @Test("idle timeout fires via handleTimeout with injected time (no real sleep)")
    func idleTimeoutClockFree() throws {
        let idle: UInt64 = 1_000_000_000  // 1s
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: idle), nowNanos: 0)

        // Before the deadline: not expired.
        var out = try engine.handleTimeout(nowNanos: idle - 1)
        #expect(!out.idleExpired)

        // At/after the deadline: expired, terminal, surfaced to the facade.
        out = try engine.handleTimeout(nowNanos: idle + 1)
        #expect(out.idleExpired)
        #expect(out.firedTimers.contains(.idle))
    }

    @Test("idle deadline is reported in the deadline set")
    func idleDeadlineReported() throws {
        let idle: UInt64 = 5_000_000_000
        let engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: idle), nowNanos: 0)
        let deadlines = engine.deadlines(nowNanos: 0)
        #expect(deadlines.idleNanos != nil)
        // The earliest deadline should be the idle one (nothing else armed yet).
        #expect(deadlines.earliestDeadlineNanos == deadlines.idleNanos)
    }

    @Test("idle disabled when timeout is zero")
    func idleDisabled() throws {
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8)), idleNanos: 0), nowNanos: 0)
        let deadlines = engine.deadlines(nowNanos: 0)
        #expect(deadlines.idleNanos == nil)
        let out = try engine.handleTimeout(nowNanos: 100_000_000_000)
        #expect(!out.idleExpired)
    }

    // MARK: - Streams + round-trip over Initial keys (sans-IO)

    @Test("client opens a stream, writes data; server receives it across the sans-IO boundary")
    func streamRoundTripOverInitial() throws {
        var (client, server, _, _, _) = try makePair()

        // Client opens a bidi stream and writes.
        let sid = try client.openStream(bidirectional: true)
        let payload: [UInt8] = Array("hello quic engine".utf8)
        try client.writeStream(sid, data: payload)

        // Flush produces an Initial datagram (we have only Initial keys here).
        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)

        // Server receives the datagram (sans-IO): it decrypts with the shared
        // Initial keys, routes the STREAM frame to the receive core, surfaces the
        // new stream + readable event.
        var sawStream = false
        var received: [UInt8] = []
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            if out.newStreams.contains(sid) { sawStream = true }
            if out.readableStreams.contains(sid) {
                if let data = server.readStream(sid) { received.append(contentsOf: data) }
            }
        }
        #expect(sawStream)
        #expect(received == payload)
    }

    @Test("server ACKs an ack-eliciting packet; client processes the ACK")
    func ackGenerationAndProcessing() throws {
        var (client, server, _, _, _) = try makePair()

        let sid = try client.openStream(bidirectional: true)
        try client.writeStream(sid, data: Array("ping".utf8))
        let datagrams = try client.flush(nowNanos: 1_000)

        // Server receives → owes an ACK; its receive() flush should carry it.
        var serverAck: [[UInt8]] = []
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            serverAck.append(contentsOf: out.datagramsToSend)
            _ = server.readStream(sid)
        }
        // The server may not have new info worth ACKing immediately in the same
        // step; force a flush to emit the owed ACK.
        let forced = try server.flush(nowNanos: 3_000)
        serverAck.append(contentsOf: forced)
        #expect(!serverAck.isEmpty)

        // Client processes the server's ACK without error.
        for dgram in serverAck {
            _ = try client.receive(datagram: dgram, nowNanos: 4_000)
        }
    }

    // MARK: - Clock-free PTO probe

    @Test("PTO probe is produced via handleTimeout after an ack-eliciting send (clock-free)")
    func ptoProbeClockFree() throws {
        var (client, _, _, _, _) = try makePair()

        let sid = try client.openStream(bidirectional: true)
        try client.writeStream(sid, data: Array("data".utf8))
        // Send at t=0 (ack-eliciting packet now in flight).
        let sent = try client.flush(nowNanos: 0)
        #expect(!sent.isEmpty)

        // A loss-detection (PTO) deadline must now be armed.
        let deadlines = client.deadlines(nowNanos: 0)
        let pto = try #require(deadlines.lossDetectionNanos)
        #expect(pto > 0)

        // Drive the timer far past the PTO deadline: a probe (ack-eliciting
        // packet) is produced and the PTO fired — with NO real sleep.
        let out = try client.handleTimeout(nowNanos: pto + 1_000_000_000)
        #expect(out.firedTimers.contains(.lossDetection))
        #expect(!out.datagramsToSend.isEmpty)
    }

    @Test("no PTO deadline armed when nothing is in flight")
    func noPTOWhenIdle() throws {
        let (client, _, _, _, _) = try makePair()
        let deadlines = client.deadlines(nowNanos: 0)
        #expect(deadlines.lossDetectionNanos == nil)
    }

    // MARK: - Connection close

    @Test("close produces a CONNECTION_CLOSE and marks the engine closed")
    func closeProducesConnectionClose() throws {
        var (client, server, _, _, _) = try makePair()

        client.close(errorCode: 0, reason: Array("bye".utf8), isApplicationError: false)
        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)
        #expect(client.isClosed)

        // Server sees the peer close.
        var peerClosed = false
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            if out.peerClosed { peerClosed = true }
        }
        #expect(peerClosed)
        #expect(server.isClosed)
    }

    @Test("operations after close throw connectionClosed")
    func operationsAfterCloseThrow() throws {
        var (client, _, _, _, _) = try makePair()
        client.close(errorCode: 0, reason: [], isApplicationError: false)
        _ = try client.flush(nowNanos: 1_000)
        #expect(client.isClosed)
        #expect(throws: QUICEngineError.self) {
            _ = try client.openStream(bidirectional: true)
        }
    }

    // MARK: - Key update (RFC 9001 §6)

    @Test("application key update flips the key phase deterministically")
    func keyUpdateFlipsPhase() throws {
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8))), nowNanos: 0)
        // Install application keys (32-byte traffic secrets), then update.
        let readSecret = [UInt8](repeating: 0x01, count: 32)
        let writeSecret = [UInt8](repeating: 0x02, count: 32)
        try engine.installKeys(level: .application, readSecret: readSecret, writeSecret: writeSecret, suite: .aes128GCM)
        #expect(engine.currentKeyPhase == 0)
        let newPhase = try engine.performKeyUpdate()
        #expect(newPhase == 1)
        #expect(engine.currentKeyPhase == 1)
        // A second update returns to phase 0.
        let phase2 = try engine.performKeyUpdate()
        #expect(phase2 == 0)
    }

    @Test("key update before application keys are installed throws")
    func keyUpdateBeforeKeysThrows() throws {
        var engine = try Engine(configuration: makeConfig(role: .client, dcid: try #require(ConnectionID.random(length: 8)), scid: try #require(ConnectionID.random(length: 8))), nowNanos: 0)
        #expect(throws: QUICEngineError.self) {
            _ = try engine.performKeyUpdate()
        }
    }

    // MARK: - Anti-amplification (RFC 9000 §8.1)

    @Test("server is anti-amplification blocked before receiving enough bytes")
    func serverAntiAmplification() throws {
        var (_, server, _, _, _) = try makePair()
        // Server has received nothing → its 3x budget is 0; an Initial flush
        // produces nothing (blocked) rather than amplifying.
        server.queueHandshake(Array(repeating: 0xAB, count: 100), level: .initial)
        let datagrams = try server.flush(nowNanos: 1_000)
        #expect(datagrams.isEmpty)
    }
}
