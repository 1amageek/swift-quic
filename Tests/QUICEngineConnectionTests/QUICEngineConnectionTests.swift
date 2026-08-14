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
import NetworkingCore
import NetworkingDatagram
import NetworkingTime
import QUICTLS
import SSLCore
import SSLCrypto
import SSLX509
@testable import QUIC

private typealias Engine = QUICConnectionEngine

private struct IntegratedTLSSessions: ~Copyable {
    var client: QUICTLSClientSession
    var server: QUICTLSServerSession
}

// MARK: - In-memory loopback transport

/// Cancellation-safe single-consumer queue used by the loopback transport.
private actor LoopbackPipe {
    private struct Waiter {
        let token: UInt64
        let continuation: CheckedContinuation<Result<InboundDatagram?, DatagramError>, Never>
    }

    private var queue: [InboundDatagram] = []
    private var waiter: Waiter?
    private var nextToken: UInt64 = 0
    private var reservedTokens: Set<UInt64> = []
    private var cancelledTokens: Set<UInt64> = []
    private var closed = false

    func enqueue(_ datagram: consuming InboundDatagram) {
        guard !closed else { return }
        if let waiter {
            self.waiter = nil
            waiter.continuation.resume(returning: .success(datagram))
        } else {
            queue.append(datagram)
        }
    }

    func receive() async throws(DatagramError) -> InboundDatagram? {
        let token = nextToken
        nextToken &+= 1
        reservedTokens.insert(token)

        let result = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                registerReceive(token: token, continuation: continuation)
            }
        } onCancel: {
            Task { await self.cancelReceive(token: token) }
        }
        switch result {
        case .success(let datagram): return datagram
        case .failure(let error): throw error
        }
    }

    func shutdown() {
        guard !closed else { return }
        closed = true
        queue.removeAll(keepingCapacity: false)
        let waiter = self.waiter
        self.waiter = nil
        reservedTokens.removeAll()
        cancelledTokens.removeAll()
        waiter?.continuation.resume(returning: .success(nil))
    }

    private func registerReceive(
        token: UInt64,
        continuation: CheckedContinuation<Result<InboundDatagram?, DatagramError>, Never>
    ) {
        guard reservedTokens.remove(token) != nil else {
            continuation.resume(returning: .failure(.cancelled))
            return
        }
        if cancelledTokens.remove(token) != nil || Task.isCancelled {
            continuation.resume(returning: .failure(.cancelled))
        } else if !queue.isEmpty {
            continuation.resume(returning: .success(queue.removeFirst()))
        } else if closed {
            continuation.resume(returning: .success(nil))
        } else if waiter != nil {
            continuation.resume(returning: .failure(.concurrentReceive))
        } else {
            waiter = Waiter(token: token, continuation: continuation)
        }
    }

    private func cancelReceive(token: UInt64) {
        if reservedTokens.contains(token) {
            cancelledTokens.insert(token)
            return
        }
        guard waiter?.token == token else { return }
        let continuation = waiter?.continuation
        waiter = nil
        continuation?.resume(returning: .failure(.cancelled))
    }
}

private final class LoopbackTransport: DatagramTransport, Sendable {
    let localEndpoint: IPSocketEndpoint
    let maximumDatagramSize = 1200
    let capabilities: DatagramTransportCapabilities = []
    let receiveBuffering: DatagramReceiveBuffering

    private let pipe = LoopbackPipe()
    private let peerPipe = Mutex<LoopbackPipe?>(nil)
    private let receivedCount = Mutex<UInt64>(0)

    init(selfEndpoint: IPSocketEndpoint) throws {
        localEndpoint = selfEndpoint
        receiveBuffering = try DatagramReceiveBuffering(
            capacity: 64,
            overflowPolicy: .failTransport
        )
    }

    func connect(to peer: LoopbackTransport) {
        peerPipe.withLock { $0 = peer.pipe }
    }

    func send(
        _ payload: consuming OwnedBytes,
        to endpoint: IPSocketEndpoint,
        metadata: DatagramSendMetadata
    ) async throws(DatagramError) {
        guard let target = peerPipe.withLock({ $0 }) else {
            throw .closed
        }
        await target.enqueue(InboundDatagram(payload: payload, source: localEndpoint))
    }

    func receive() async throws(DatagramError) -> InboundDatagram? {
        let datagram = try await pipe.receive()
        if datagram != nil { receivedCount.withLock { $0 &+= 1 } }
        return datagram
    }

    func receiveStatistics() -> DatagramReceiveStatistics {
        DatagramReceiveStatistics(
            receivedDatagramCount: receivedCount.withLock { $0 },
            droppedDatagramCount: 0
        )
    }

    func shutdown() async throws(DatagramError) {
        await pipe.shutdown()
    }
}

private final class ImmediateReceiveTransport: DatagramTransport, Sendable {
    let localEndpoint: IPSocketEndpoint
    let maximumDatagramSize = 1200
    let capabilities: DatagramTransportCapabilities = []
    let receiveBuffering: DatagramReceiveBuffering
    private let receiveError: DatagramError?

    init(endpoint: IPSocketEndpoint, receiveError: DatagramError?) throws {
        localEndpoint = endpoint
        self.receiveError = receiveError
        receiveBuffering = try DatagramReceiveBuffering(
            capacity: 1,
            overflowPolicy: .failTransport
        )
    }

    func send(
        _ payload: consuming OwnedBytes,
        to endpoint: IPSocketEndpoint,
        metadata: DatagramSendMetadata
    ) async throws(DatagramError) {}

    func receive() async throws(DatagramError) -> InboundDatagram? {
        if let receiveError { throw receiveError }
        return nil
    }

    func receiveStatistics() -> DatagramReceiveStatistics {
        DatagramReceiveStatistics(receivedDatagramCount: 0, droppedDatagramCount: 0)
    }

    func shutdown() async throws(DatagramError) {}
}

private final class FailingSleepTimer: AsyncTimer, Sendable {
    func now() throws(TimeError) -> MonotonicInstant {
        return MonotonicInstant(clockIdentifier: 1, nanoseconds: 0)
    }

    func sleep(until deadline: MonotonicInstant) async throws(TimeError) {
        _ = deadline
        throw .backendFailure(code: 74)
    }
}

private typealias LoopbackRuntime = QUICRuntime<
    LoopbackTransport,
    ContinuousAsyncTimer
>
private typealias LoopbackConnection = QUICEngineConnection<LoopbackRuntime>
private typealias ImmediateRuntime = QUICRuntime<
    ImmediateReceiveTransport,
    ContinuousAsyncTimer
>
private typealias ImmediateConnection = QUICEngineConnection<ImmediateRuntime>
private typealias FailingTimerRuntime = QUICRuntime<
    LoopbackTransport,
    FailingSleepTimer
>
private typealias FailingTimerConnection = QUICEngineConnection<FailingTimerRuntime>

@Suite("QUICEngineConnection — seam-driven engine driver (Slice B)")
struct QUICEngineConnectionTests {

    // MARK: - Helpers

    private func makeConfig(
        role: QUICEngineRole,
        dcid: ConnectionID,
        scid: ConnectionID,
        originalDCID: ConnectionID
    ) -> QUICConnectionEngineConfiguration {
        var tp = TransportParametersCore()
        tp.initialMaxData = 1_000_000
        tp.initialMaxStreamDataBidiLocal = 256 * 1024
        tp.initialMaxStreamDataBidiRemote = 256 * 1024
        tp.initialMaxStreamDataUni = 256 * 1024
        tp.initialMaxStreamsBidi = 100
        tp.initialMaxStreamsUni = 100
        return QUICConnectionEngineConfiguration(
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
            configuration: makeConfig(
                role: .client,
                dcid: serverSCID,
                scid: clientSCID,
                originalDCID: dcid
            ),
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
        _ = try client.installKeys(level: .application, readSecret: serverToClient, writeSecret: clientToServer, suite: .aes128GCM)
        _ = try server.installKeys(level: .application, readSecret: clientToServer, writeSecret: serverToClient, suite: .aes128GCM)
        client.markHandshakeComplete()
        server.markHandshakeComplete()
        return (client, server)
    }

    private func endpoints() -> (client: IPSocketEndpoint, server: IPSocketEndpoint) {
        (IPSocketEndpoint(ipv4: 127, 0, 0, 1, port: 4001),
         IPSocketEndpoint(ipv4: 127, 0, 0, 1, port: 4002))
    }

    private func makeIntegratedTLSSessions() throws -> IntegratedTLSSessions {
        let instant = try VerificationInstant(
            secondsSinceUnixEpoch: 1_720_000_000,
            nanoseconds: 0
        )
        let certificateDER = deterministicCertificate()
        let certificate = try X509Certificate(der: certificateDER.span)
        let applicationProtocol = try TLS13ApplicationProtocol(
            identifier: ContiguousArray([0x68, 0x33]).span
        )
        let placeholderTransportParameters = ContiguousArray<UInt8>()

        let clientSession = try QUICTLSClientSession.make(
            random: ContiguousArray(repeating: 0x01, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x11, count: 32).span
            ),
            certificateValidator: try RFC5280TLS13ServerCertificateValidator(
                trustAnchors: [certificate]
            ),
            applicationProtocols: [applicationProtocol],
            transportParameters: placeholderTransportParameters.span,
            verificationInstant: instant
        )
        let serverSession = try QUICTLSServerSession.make(
            random: ContiguousArray(repeating: 0x02, count: 32).span,
            ephemeralKey: X25519PrivateKey(
                bytes: ContiguousArray(repeating: 0x22, count: 32).span
            ),
            certificateDER: certificateDER.span,
            signingKey: TLS13SigningKey(
                ed25519: try Ed25519PrivateKey(seed: deterministicSeed().span)
            ),
            verificationInstant: instant,
            applicationProtocolSelector:
                try ServerPreferredTLS13ApplicationProtocolSelector(
                    supportedProtocols: [applicationProtocol]
                ),
            transportParameters: placeholderTransportParameters.span
        )
        return IntegratedTLSSessions(
            client: consume clientSession,
            server: consume serverSession
        )
    }

    private func deterministicSeed() -> ContiguousArray<UInt8> {
        [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ]
    }

    private func deterministicCertificate() -> ContiguousArray<UInt8> {
        [
            0x30, 0x81, 0xa6, 0x30, 0x5a, 0x02, 0x01, 0x01,
            0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x30,
            0x00, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30,
            0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x31,
            0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x5a, 0x30, 0x00, 0x30, 0x2a, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7,
            0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5,
            0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e,
            0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf,
            0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a, 0x30,
            0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x41,
            0x00, 0x37, 0xdf, 0xbf, 0x24, 0xeb, 0x69, 0x2e,
            0x0b, 0xe9, 0x24, 0x3a, 0x10, 0xe9, 0x0e, 0x7a,
            0x42, 0x05, 0x28, 0xf6, 0xdc, 0xd6, 0x03, 0x28,
            0x98, 0xdc, 0xa9, 0x56, 0xd5, 0x1c, 0xe3, 0xa2,
            0x86, 0xb1, 0x55, 0x96, 0x38, 0x08, 0x32, 0xa6,
            0x0c, 0xc5, 0x7d, 0x2a, 0x84, 0xf8, 0x43, 0xc7,
            0x74, 0xff, 0xe0, 0xa7, 0xb4, 0x62, 0xa9, 0x55,
            0x6f, 0x76, 0x75, 0x1a, 0x87, 0x0d, 0x5c, 0x79,
            0x01,
        ]
    }

    // MARK: - Construction

    @Test("driver constructs over the seams and reflects engine state")
    func constructs() throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let clientT = try LoopbackTransport(selfEndpoint: clientEP)
        let conn = LoopbackConnection(
            engine: client, transport: clientT, timer: ContinuousAsyncTimer(), peer: serverEP)
        #expect(conn.isEstablished)
        #expect(!conn.isClosed)
    }

    @Test("run exits when the transport incoming stream finishes", .timeLimit(.minutes(1)))
    func runExitsWhenTransportIncomingFinishes() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let clientT = try LoopbackTransport(selfEndpoint: clientEP)
        let conn = LoopbackConnection(
            engine: client, transport: clientT, timer: ContinuousAsyncTimer(), peer: serverEP)

        let runTask = Task { try await conn.run() }

        try await clientT.shutdown()

        let completed = await withTaskGroup(of: Bool.self) { group in
            group.addTask {
                _ = await runTask.result
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

    @Test("run preserves a terminal transport failure", .timeLimit(.minutes(1)))
    func runPreservesTransportFailure() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let expected = DatagramError.backendFailure(
            operation: .receive,
            code: 54,
            terminal: true
        )
        let transport = try ImmediateReceiveTransport(
            endpoint: clientEP,
            receiveError: expected
        )
        let connection = ImmediateConnection(
            engine: client,
            transport: transport,
            timer: ContinuousAsyncTimer(),
            peer: serverEP
        )

        do throws(QUICConnectionDriverError) {
            try await connection.run()
            Issue.record("Terminal transport failure was reported as clean shutdown")
        } catch let error {
            switch error {
            case .transport(let actual):
                #expect(actual == expected)
            default:
                Issue.record("Unexpected driver error: \(error)")
            }
        }
        #expect(connection.isClosed)
    }

    @Test("run preserves a terminal timer failure", .timeLimit(.minutes(1)))
    func runPreservesTimerFailure() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let transport = try LoopbackTransport(selfEndpoint: clientEP)
        let connection = FailingTimerConnection(
            engine: client,
            transport: transport,
            timer: FailingSleepTimer(),
            peer: serverEP
        )

        do throws(QUICConnectionDriverError) {
            try await connection.run()
            Issue.record("Terminal timer failure was reported as clean shutdown")
        } catch let error {
            switch error {
            case .time(.backendFailure(let code)):
                #expect(code == 74)
            default:
                Issue.record("Unexpected timer error: \(error)")
            }
        }
        #expect(connection.isClosed)
    }

    @Test("run is single-owner and rejects a second invocation", .timeLimit(.minutes(1)))
    func runRejectsSecondInvocation() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let transport = try ImmediateReceiveTransport(endpoint: clientEP, receiveError: nil)
        let connection = ImmediateConnection(
            engine: client,
            transport: transport,
            timer: ContinuousAsyncTimer(),
            peer: serverEP
        )

        try await connection.run()
        do throws(QUICConnectionDriverError) {
            try await connection.run()
            Issue.record("A second run invocation must fail")
        } catch let error {
            switch error {
            case .engine(.invalidState): break
            default: Issue.record("Unexpected second-run error: \(error)")
            }
        }
    }

    @Test("run preserves task cancellation", .timeLimit(.minutes(1)))
    func runPreservesTaskCancellation() async throws {
        let (client, _) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()
        let transport = try LoopbackTransport(selfEndpoint: clientEP)
        let connection = LoopbackConnection(
            engine: client,
            transport: transport,
            timer: ContinuousAsyncTimer(),
            peer: serverEP
        )

        let runTask = Task { () -> QUICConnectionDriverError? in
            do throws(QUICConnectionDriverError) {
                try await connection.run()
                return nil
            } catch let error {
                return error
            }
        }
        runTask.cancel()

        if let error = await runTask.value {
            switch error {
            case .cancelled:
                break
            default:
                Issue.record("Unexpected cancellation error: \(error)")
            }
        } else {
            Issue.record("Task cancellation was reported as clean shutdown")
        }
        #expect(connection.isClosed)
    }

    @Test("immediate clean shutdown cannot strand the timer waiter", .timeLimit(.minutes(1)))
    func immediateShutdownDoesNotStrandTimerWaiter() async throws {
        let (clientEP, serverEP) = endpoints()
        for _ in 0..<128 {
            let (client, _) = try makeEstablishedPair()
            let transport = try ImmediateReceiveTransport(endpoint: clientEP, receiveError: nil)
            let connection = ImmediateConnection(
                engine: client,
                transport: transport,
                timer: ContinuousAsyncTimer(),
                peer: serverEP
            )
            try await connection.run()
        }
    }

    // MARK: - Application-data round trip over the seams

    @Test("real swift-tls handshake establishes QUIC and carries a stream", .timeLimit(.minutes(1)))
    func integratedTLSHandshakeAndStreamRoundTrip() async throws {
        let sessions = try makeIntegratedTLSSessions()
        let dcid = try #require(ConnectionID.random(length: 8))
        let clientSCID = try #require(ConnectionID.random(length: 8))
        let serverSCID = try #require(ConnectionID.random(length: 8))
        let (clientEP, serverEP) = endpoints()
        let clientTransport = try LoopbackTransport(selfEndpoint: clientEP)
        let serverTransport = try LoopbackTransport(selfEndpoint: serverEP)
        clientTransport.connect(to: serverTransport)
        serverTransport.connect(to: clientTransport)

        let client = try QUICClient<
            QUICClientRuntime<
                LoopbackTransport,
                ContinuousAsyncTimer,
                NoExternalQUICTLSCapabilities
            >
        >(
            configuration: makeConfig(
                role: .client,
                dcid: dcid,
                scid: clientSCID,
                originalDCID: dcid
            ),
            tlsSession: sessions.client,
            transport: clientTransport,
            timer: ContinuousAsyncTimer(),
            peer: serverEP
        )
        let server = try QUICServerConnection<
            QUICServerRuntime<
                LoopbackTransport,
                ContinuousAsyncTimer,
                NoExternalQUICTLSCapabilities
            >
        >(
            configuration: makeConfig(
                role: .server,
                dcid: clientSCID,
                scid: serverSCID,
                originalDCID: dcid
            ),
            tlsSession: sessions.server,
            transport: serverTransport,
            timer: ContinuousAsyncTimer(),
            peer: clientEP
        )

        let serverLoop = Task { try await server.run() }
        let clientLoop = Task { try await client.run() }

        for _ in 0..<400 {
            if client.isEstablished && server.isEstablished { break }
            try await Task.sleep(for: .milliseconds(5))
        }
        #expect(client.isEstablished)
        #expect(server.isEstablished)

        let payload = Array("real-tls-over-quic".utf8)
        let streamID = try client.openStream(bidirectional: true)
        try await client.writeStream(streamID, data: payload)

        var received: [UInt8] = []
        for _ in 0..<400 {
            for readableID in server.takeReadableStreams() where readableID == streamID {
                if let chunk = server.readStream(readableID) {
                    received.append(contentsOf: chunk)
                }
            }
            if received == payload { break }
            try await Task.sleep(for: .milliseconds(5))
        }

        clientLoop.cancel()
        serverLoop.cancel()
        try await clientTransport.shutdown()
        try await serverTransport.shutdown()

        _ = await clientLoop.result
        _ = await serverLoop.result

        #expect(received == payload)
    }

    @Test("client STREAM write surfaces on the server via the seam-driven loops")
    func streamRoundTrip() async throws {
        let (client, server) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()

        let clientT = try LoopbackTransport(selfEndpoint: clientEP)
        let serverT = try LoopbackTransport(selfEndpoint: serverEP)
        clientT.connect(to: serverT)
        serverT.connect(to: clientT)

        let clientConn = LoopbackConnection(
            engine: client, transport: clientT, timer: ContinuousAsyncTimer(), peer: serverEP)
        let serverConn = LoopbackConnection(
            engine: server, transport: serverT, timer: ContinuousAsyncTimer(), peer: clientEP)

        // Run both connections' I/O + timer loops.
        let clientLoop = Task { try await clientConn.run() }
        let serverLoop = Task { try await serverConn.run() }

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
        let serverReceiveCount = serverT.receiveStatistics().receivedDatagramCount
        let serverClosed = serverConn.isClosed

        clientLoop.cancel()
        serverLoop.cancel()
        try await clientT.shutdown()
        try await serverT.shutdown()
        _ = await clientLoop.result
        _ = await serverLoop.result

        #expect(serverReceiveError == nil, "server receive errored: \(String(describing: serverReceiveError))")
        #expect(serverReceiveCount > 0, "server transport did not receive a datagram")
        #expect(!serverClosed, "server connection closed before the stream became readable")
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

    @Test("a FIN-only STREAM frame surfaces readable EOF activity")
    func finOnlyFrameSurfacesReadableActivity() throws {
        var (client, server) = try makeEstablishedPair()
        let streamID = try client.openStream(bidirectional: true)

        try client.writeStream(streamID, data: [0x41])
        for datagram in try client.flush(nowNanos: 1_000) {
            let output = try server.receive(
                datagram: datagram,
                nowNanos: 2_000
            )
            #expect(output.readableStreams.contains(streamID))
        }
        #expect(server.readStream(streamID) == [0x41])
        #expect(!server.streamReadFinished(streamID))

        try client.finishStream(streamID)
        var observedEOFActivity = false
        for datagram in try client.flush(nowNanos: 3_000) {
            let output = try server.receive(
                datagram: datagram,
                nowNanos: 4_000
            )
            if output.readableStreams.contains(streamID) {
                observedEOFActivity = true
            }
        }

        #expect(observedEOFActivity)
        #expect(server.streamReadFinished(streamID))
    }

    // MARK: - Close

    @Test("close sends a CONNECTION_CLOSE the peer observes")
    func closePropagates() async throws {
        let (client, server) = try makeEstablishedPair()
        let (clientEP, serverEP) = endpoints()

        let clientT = try LoopbackTransport(selfEndpoint: clientEP)
        let serverT = try LoopbackTransport(selfEndpoint: serverEP)
        clientT.connect(to: serverT)
        serverT.connect(to: clientT)

        let clientConn = LoopbackConnection(
            engine: client, transport: clientT, timer: ContinuousAsyncTimer(), peer: serverEP)
        let serverConn = LoopbackConnection(
            engine: server, transport: serverT, timer: ContinuousAsyncTimer(), peer: clientEP)

        let serverLoop = Task { try await serverConn.run() }

        try await clientConn.close(errorCode: 0, reason: Array("bye".utf8), isApplicationError: true)

        var observed = false
        for _ in 0..<200 {
            if serverConn.peerCloseReason != nil { observed = true; break }
            try await Task.sleep(for: .milliseconds(5))
        }

        serverLoop.cancel()
        try await clientT.shutdown()
        try await serverT.shutdown()
        _ = await serverLoop.result

        #expect(observed)
        #expect(clientConn.isClosed)
    }
}
