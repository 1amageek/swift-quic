// QUICEngineConnectionTests.swift
// Host tests for the seam-driven `QUICEngineConnection` driver (quic Slice B).
//
// These drive the FacadeLock<engine> + DatagramTransport + AsyncTimer rewire
// end-to-end over an in-memory loopback transport pair and a host AsyncTimer,
// proving the I/O inversion (transport.incoming -> engine.receive -> transport.send)
// and the application-data path round-trip. They add coverage; they weaken no
// existing security test (packet protection, flow control, ACK/loss, etc. are
// still owned by the engine + cores).

import Testing
import Synchronization
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICConnectionEngineCore
import P2PCrypto
import P2PCoreCrypto
import P2PCoreTransport
@testable import QUIC

private typealias Provider = DefaultCryptoProvider
private typealias Engine = QUICConnectionEngine<Provider, AsyncTimerClock>

// MARK: - In-memory loopback transport

/// A pair-wired in-memory `DatagramTransport`: bytes sent on one side surface on
/// the other side's `incoming`. No sockets — deterministic, host-only test double.
private final class LoopbackTransport: DatagramTransport, @unchecked Sendable {
    typealias Incoming = AsyncStream<Datagram>

    let maximumDatagramSize = 1200
    let incoming: AsyncStream<Datagram>
    private let inboundContinuation: AsyncStream<Datagram>.Continuation
    private let peerContinuation: Mutex<AsyncStream<Datagram>.Continuation?>
    private let selfEndpoint: SocketEndpoint

    init(selfEndpoint: SocketEndpoint) {
        self.selfEndpoint = selfEndpoint
        var cont: AsyncStream<Datagram>.Continuation!
        self.incoming = AsyncStream<Datagram> { cont = $0 }
        self.inboundContinuation = cont
        self.peerContinuation = Mutex(nil)
    }

    /// Wires this transport to deliver its sends into `peer`'s incoming stream.
    func connect(to peer: LoopbackTransport) {
        peerContinuation.withLock { $0 = peer.inboundContinuation }
    }

    func send(_ payload: Span<UInt8>, to endpoint: SocketEndpoint) async throws(TransportError) {
        var bytes: [UInt8] = []
        bytes.reserveCapacity(payload.count)
        for i in payload.indices { bytes.append(payload[i]) }
        let target = peerContinuation.withLock { $0 }
        target?.yield(Datagram(payload: bytes, source: selfEndpoint))
    }

    func close() async {
        inboundContinuation.finish()
        peerContinuation.withLock { $0?.finish() }
    }
}

@Suite("QUICEngineConnection — seam-driven engine driver (Slice B)")
struct QUICEngineConnectionTests {

    // MARK: - Helpers

    private func makeConfig(
        role: QUICEngineRole,
        dcid: ConnectionID,
        scid: ConnectionID,
        originalDCID: ConnectionID
    ) -> QUICConnectionEngineConfiguration<Provider> {
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
            originalDestinationConnectionID: originalDCID,
            localTransportParameters: tp,
            maxDatagramSize: 1200,
            idleTimeoutNanos: 30_000_000_000,
            maxAckDelayNanos: 25_000_000,
            pathValidationTimeoutNanos: 3_000_000_000
        )
    }

    /// Builds a fully-established client+server engine pair with matching 1-RTT
    /// keys and validated path (post-handshake state), mirroring the engine
    /// tests' `makePair`.
    private func makeEstablishedPair() throws -> (client: Engine, server: Engine) {
        let dcid = try #require(ConnectionID.random(length: 8))
        let clientSCID = try #require(ConnectionID.random(length: 8))
        let serverSCID = try #require(ConnectionID.random(length: 8))

        var client = try Engine(
            configuration: makeConfig(role: .client, dcid: dcid, scid: clientSCID, originalDCID: dcid),
            nowNanos: 0)
        var server = try Engine(
            configuration: makeConfig(role: .server, dcid: clientSCID, scid: serverSCID, originalDCID: dcid),
            nowNanos: 0)

        var peerTP = TransportParametersCore()
        peerTP.initialMaxData = 1_000_000
        peerTP.initialMaxStreamDataBidiLocal = 256 * 1024
        peerTP.initialMaxStreamDataBidiRemote = 256 * 1024
        peerTP.initialMaxStreamDataUni = 256 * 1024
        peerTP.initialMaxStreamsBidi = 100
        peerTP.initialMaxStreamsUni = 100
        client.applyPeerTransportParameters(peerTP)
        server.applyPeerTransportParameters(peerTP)

        let clientToServer = [UInt8](repeating: 0xC0, count: 32)
        let serverToClient = [UInt8](repeating: 0x05, count: 32)
        try client.installKeys(level: .application, readSecret: serverToClient, writeSecret: clientToServer, suite: .aes128GCM)
        try server.installKeys(level: .application, readSecret: clientToServer, writeSecret: serverToClient, suite: .aes128GCM)
        client.markHandshakeComplete()
        server.markHandshakeComplete()
        return (client, server)
    }

    private func endpoints() -> (client: SocketEndpoint, server: SocketEndpoint) {
        (SocketEndpoint(v4: 127, 0, 0, 1, port: 4001),
         SocketEndpoint(v4: 127, 0, 0, 1, port: 4002))
    }

    // MARK: - Construction

    @Test("driver constructs over the seams and reflects engine state")
    func constructs() throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let clientT = LoopbackTransport(selfEndpoint: clientEP)
        let conn = QUICEngineConnection(
            engine: client, transport: clientT, timer: AsyncTimerClock(), peer: serverEP)
        #expect(conn.isEstablished)
        #expect(!conn.isClosed)
    }

    @Test("run exits when the transport incoming stream finishes", .timeLimit(.minutes(1)))
    func runExitsWhenTransportIncomingFinishes() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let clientT = LoopbackTransport(selfEndpoint: clientEP)
        let conn = QUICEngineConnection(
            engine: client, transport: clientT, timer: AsyncTimerClock(), peer: serverEP)

        let runTask = Task { await conn.run() }

        await clientT.close()

        let completed = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                await runTask.value
                return true
            }
            group.addTask {
                do {
                    try await Task.sleep(for: .milliseconds(200))
                } catch {
                    return false
                }
                return false
            }
            let completed = await group.next() ?? false
            group.cancelAll()
            return completed
        }

        if !completed {
            runTask.cancel()
        }
        #expect(completed)
        #expect(conn.isClosed)
    }

    // MARK: - Application-data round trip over the seams

    @Test("client STREAM write surfaces on the server via the seam-driven loops")
    func streamRoundTrip() async throws {
        let (client, server) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()

        let clientT = LoopbackTransport(selfEndpoint: clientEP)
        let serverT = LoopbackTransport(selfEndpoint: serverEP)
        clientT.connect(to: serverT)
        serverT.connect(to: clientT)

        let clientConn = QUICEngineConnection(
            engine: client, transport: clientT, timer: AsyncTimerClock(), peer: serverEP)
        let serverConn = QUICEngineConnection(
            engine: server, transport: serverT, timer: AsyncTimerClock(), peer: clientEP)

        // Run both connections' I/O + timer loops.
        let clientLoop = Task { await clientConn.run() }
        let serverLoop = Task { await serverConn.run() }

        // Client opens a stream and writes; the engine frames + the driver sends it.
        let payload: [UInt8] = Array("hello-quic-slice-b".utf8)
        let streamID = try clientConn.openStream(bidirectional: true)
        try await clientConn.writeStream(streamID, data: payload)

        // The server's receive loop should surface the new stream + readable data.
        // Accumulate every stream the peer touched and try draining each (readStream
        // is non-destructive when empty), so we never miss a one-shot event.
        var candidates: Set<UInt64> = []
        var received: [UInt8] = []
        for _ in 0..<200 {
            for id in serverConn.takeNewStreams() { candidates.insert(id) }
            for id in serverConn.takeReadableStreams() { candidates.insert(id) }
            for id in candidates {
                if let data = serverConn.readStream(id), !data.isEmpty {
                    received.append(contentsOf: data)
                }
            }
            if received == payload { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        let serverReceiveError = serverConn.lastReceiveError

        clientLoop.cancel()
        serverLoop.cancel()
        await clientT.close()
        await serverT.close()

        #expect(serverReceiveError == nil, "server receive errored: \(String(describing: serverReceiveError))")
        #expect(received == payload)
    }

    @Test("engine-level sanity: client flush decrypts + routes on the server")
    func engineLevelSanity() throws {
        var (client, server) = try makeEstablishedPair()
        let sid = try client.openStream(bidirectional: true)
        let payload: [UInt8] = Array("hello".utf8)
        try client.writeStream(sid, data: payload)
        let datagrams = try client.flush(nowNanos: 1_000)
        #expect(!datagrams.isEmpty)
        var received: [UInt8] = []
        var sawStream = false
        for dgram in datagrams {
            let out = try server.receive(datagram: dgram, nowNanos: 2_000)
            if out.newStreams.contains(sid) { sawStream = true }
            if out.readableStreams.contains(sid), let data = server.readStream(sid) {
                received.append(contentsOf: data)
            }
        }
        #expect(sawStream)
        #expect(received == payload)
    }

    // MARK: - Close

    @Test("close sends a CONNECTION_CLOSE the peer observes")
    func closePropagates() async throws {
        let (client, server) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()

        let clientT = LoopbackTransport(selfEndpoint: clientEP)
        let serverT = LoopbackTransport(selfEndpoint: serverEP)
        clientT.connect(to: serverT)
        serverT.connect(to: clientT)

        let clientConn = QUICEngineConnection(
            engine: client, transport: clientT, timer: AsyncTimerClock(), peer: serverEP)
        let serverConn = QUICEngineConnection(
            engine: server, transport: serverT, timer: AsyncTimerClock(), peer: clientEP)

        let serverLoop = Task { await serverConn.run() }

        await clientConn.close(errorCode: 0, reason: Array("bye".utf8), isApplicationError: true)

        var observed = false
        for _ in 0..<200 {
            if serverConn.peerCloseReason != nil { observed = true; break }
            try await Task.sleep(for: .milliseconds(5))
        }

        serverLoop.cancel()
        await clientT.close()
        await serverT.close()

        #expect(observed)
        #expect(clientConn.isClosed)
    }
}
