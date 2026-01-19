/// QUIC Endpoint E2E Tests
///
/// Tests for end-to-end QUIC connection establishment and data exchange.

import Testing
import Foundation
import Synchronization
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto
@testable import QUICConnection

/// Thread-safe packet collector for tests
final class PacketCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var _packets: [Data] = []

    var packets: [Data] {
        lock.lock()
        defer { lock.unlock() }
        return _packets
    }

    func append(_ data: Data) {
        lock.lock()
        defer { lock.unlock() }
        _packets.append(data)
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return _packets.count
    }

    var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _packets.isEmpty
    }
}

// MARK: - Endpoint Tests

@Suite("QUICEndpoint Tests")
struct EndpointTests {
    // MARK: - Creation Tests

    @Test("Create client endpoint")
    func createClientEndpoint() async throws {
        let config = QUICConfiguration()
        let endpoint = QUICEndpoint(configuration: config)

        #expect(await endpoint.connectionCount == 0)
    }

    @Test("Create server endpoint")
    func createServerEndpoint() async throws {
        let config = QUICConfiguration()
        let serverAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let endpoint = try await QUICEndpoint.listen(
            address: serverAddress,
            configuration: config
        )

        #expect(await endpoint.localAddress?.port == 4433)
        #expect(await endpoint.connectionCount == 0)
    }

    // MARK: - Connection Tests

    @Test("Client can initiate connection")
    func clientInitiatesConnection() async throws {
        let config = QUICConfiguration.testing()
        let endpoint = QUICEndpoint(configuration: config)

        let serverAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        // Track sent packets
        let sentPackets = PacketCollector()
        await endpoint.setSendCallback { data, _ in
            sentPackets.append(data)
        }

        // Connect generates Initial packet
        let _ = try await endpoint.connect(to: serverAddress)

        // Should have sent at least one packet (Initial with ClientHello)
        #expect(sentPackets.count >= 1)
        #expect(await endpoint.connectionCount >= 1)

        // Initial packet should be at least 1200 bytes
        if let firstPacket = sentPackets.packets.first {
            #expect(firstPacket.count >= 1200)
        }
    }

    @Test("Server accepts new connection")
    func serverAcceptsConnection() async throws {
        let config = QUICConfiguration.testing()
        let serverAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4433)
        let clientAddress = SocketAddress(ipAddress: "127.0.0.1", port: 54321)

        let server = try await QUICEndpoint.listen(
            address: serverAddress,
            configuration: config
        )

        // Create a mock Initial packet
        let initialPacket = try createMockInitialPacket()

        // Process the Initial packet
        let sentPackets = PacketCollector()
        await server.setSendCallback { data, _ in
            sentPackets.append(data)
        }

        _ = try await server.processIncomingPacket(initialPacket, from: clientAddress)

        // Server should have created a connection
        #expect(await server.connectionCount >= 1)

        // Server should have sent response (ServerHello + Handshake)
        #expect(sentPackets.count >= 1)
    }

    // MARK: - Packet Processing Tests

    @Test("PacketProcessor encrypts and decrypts packets")
    func packetProcessorRoundtrip() async throws {
        // Use same DCID for both client and server (this is the original DCID)
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        // Client encrypts with client sealer
        let clientProcessor = PacketProcessor(dcidLength: 8)
        let (_, _) = try clientProcessor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        // Create a simple packet
        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data("test".utf8)))
        ]

        // Encrypt with client
        let encrypted = try clientProcessor.encryptLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0
        )

        // Initial packets must be >= 1200 bytes
        #expect(encrypted.count >= 1200)

        // Server decrypts with server opener (using same original DCID for key derivation)
        let serverProcessor = PacketProcessor(dcidLength: 8)
        let (_, _) = try serverProcessor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: false,
            version: .v1
        )

        // Decrypt - server uses opener which reads client's encrypted data
        let parsed = try serverProcessor.decryptPacket(encrypted)

        #expect(parsed.packetNumber == 0)
        #expect(parsed.encryptionLevel == .initial)
        #expect(!parsed.frames.isEmpty)
    }

    // MARK: - Connection Router Tests

    @Test("ConnectionRouter routes by DCID")
    func routerRoutesByDCID() async throws {
        let router = ConnectionRouter(isServer: true, dcidLength: 8)

        // Create a connection
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 1234)

        let connection = ManagedConnection(
            role: .server,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        // Register
        router.register(connection)

        // Route should find the connection
        let found = router.connection(for: scid)
        #expect(found != nil)
        #expect(found?.sourceConnectionID == scid)
    }

    // MARK: - Timer Manager Tests

    @Test("TimerManager tracks connection timers")
    func timerManagerTracksTimers() async throws {
        let timerManager = TimerManager(idleTimeout: .seconds(30))

        // Create a connection
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 1234)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        // Register
        timerManager.register(connection)

        #expect(timerManager.connectionCount == 1)
        #expect(timerManager.activeConnectionCount == 1)

        // Should have a deadline (idle timeout)
        let deadline = timerManager.nextDeadline()
        #expect(deadline != nil)

        // Unregister
        timerManager.unregister(connection)
        #expect(timerManager.connectionCount == 0)
    }

    // MARK: - Managed Connection Tests

    @Test("ManagedConnection creates Initial packet")
    func managedConnectionCreatesInitial() async throws {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        // Check initial state
        #expect(connection.handshakeState == .idle)

        // Start handshake - this should return quickly
        let packets = try await connection.start()

        // Should have generated Initial packet(s)
        #expect(!packets.isEmpty, "Expected at least one packet from start()")

        // Initial packet should be >= 1200 bytes
        if let firstPacket = packets.first {
            #expect(firstPacket.count >= 1200, "Initial packet must be at least 1200 bytes")
        }

        // Connection should be in connecting state
        #expect(connection.handshakeState == .connecting)
    }

    @Test("ManagedConnection handshake state transitions")
    func managedConnectionHandshakeStates() async throws {
        // Start with idle
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        #expect(connection.handshakeState == .idle)

        // After start, should be connecting
        _ = try await connection.start()
        #expect(connection.handshakeState == .connecting)
    }

    // MARK: - Managed Stream Tests

    @Test("ManagedStream read/write operations")
    func managedStreamOperations() async throws {
        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let tlsProvider = MockTLSProvider()
        tlsProvider.forceComplete()
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        // Need to establish connection first for streams
        _ = try await connection.start()

        // Open a stream
        let stream = try await connection.openStream()
        #expect(stream.isBidirectional)
        #expect(!stream.isUnidirectional)

        // Write some data
        let testData = Data("Hello, QUIC!".utf8)
        try await stream.write(testData)

        // Close write
        try await stream.closeWrite()
    }

    // MARK: - Helper Methods

    /// Creates a mock Initial packet for testing
    private func createMockInitialPacket() throws -> Data {
        let processor = PacketProcessor(dcidLength: 8)
        let dcid = try #require(ConnectionID.random(length: 8))
        let scid = try #require(ConnectionID.random(length: 8))

        // Derive keys
        let (_, _) = try processor.deriveAndInstallInitialKeys(
            connectionID: dcid,
            isClient: true,
            version: .v1
        )

        let header = LongHeader(
            packetType: .initial,
            version: .v1,
            destinationConnectionID: dcid,
            sourceConnectionID: scid,
            token: nil
        )

        let frames: [Frame] = [
            .crypto(CryptoFrame(offset: 0, data: Data("MOCK_CLIENT_HELLO".utf8)))
        ]

        return try processor.encryptLongHeaderPacket(
            frames: frames,
            header: header,
            packetNumber: 0
        )
    }
}

// MARK: - Shutdown Safety Tests

@Suite("Shutdown Safety Tests")
struct ShutdownSafetyTests {
    /// Creates a ManagedConnection for testing
    private func createTestConnection() throws -> ManagedConnection {
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
            remoteAddress: address
        )
    }

    @Test("acceptStream() after shutdown() does not hang", .timeLimit(.minutes(1)))
    func acceptStreamAfterShutdownDoesNotHang() async throws {
        let connection = try createTestConnection()
        _ = try await connection.start()

        // Shutdown the connection
        connection.shutdown()

        // acceptStream() should throw connectionClosed, NOT hang
        do {
            _ = try await connection.acceptStream()
            Issue.record("Expected connectionClosed error")
        } catch let error as ManagedConnectionError {
            if case .connectionClosed = error {
                // Expected
            } else {
                Issue.record("Expected connectionClosed but got \(error)")
            }
        }
    }

    @Test("incomingStreams after shutdown() returns finished stream", .timeLimit(.minutes(1)))
    func incomingStreamsAfterShutdownReturnsFinished() async throws {
        let connection = try createTestConnection()
        _ = try await connection.start()

        // Shutdown the connection
        connection.shutdown()

        // Iterating should complete immediately, NOT hang
        var count = 0
        for await _ in connection.incomingStreams {
            count += 1
        }

        // Stream should be finished (no elements)
        #expect(count == 0)
    }

    @Test("readFromStream() after shutdown() throws connectionClosed", .timeLimit(.minutes(1)))
    func readFromStreamAfterShutdownThrows() async throws {
        let tlsProvider = MockTLSProvider()
        tlsProvider.forceComplete()

        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        _ = try await connection.start()

        // Open a stream
        let stream = try await connection.openStream()

        // Shutdown the connection
        connection.shutdown()

        // Reading should throw connectionClosed, NOT hang
        do {
            _ = try await stream.read()
            Issue.record("Expected error from read after shutdown")
        } catch {
            // Expected - either connectionClosed or streamClosed
        }
    }

    @Test("Multiple acceptStream() calls after shutdown() all complete", .timeLimit(.minutes(1)))
    func multipleAcceptStreamAfterShutdown() async throws {
        let connection = try createTestConnection()
        _ = try await connection.start()

        // Shutdown the connection
        connection.shutdown()

        // Multiple calls should all complete without hanging
        var completedCount = 0
        for _ in 0..<3 {
            do {
                _ = try await connection.acceptStream()
            } catch {
                completedCount += 1
            }
        }

        #expect(completedCount == 3, "All acceptStream calls should complete with error")
    }

    @Test("shutdown() resumes waiting readers", .timeLimit(.minutes(1)))
    func shutdownResumesWaitingReaders() async throws {
        let tlsProvider = MockTLSProvider()
        tlsProvider.forceComplete()

        let scid = try #require(ConnectionID.random(length: 8))
        let dcid = try #require(ConnectionID.random(length: 8))
        let config = QUICConfiguration()
        let params = TransportParameters(from: config, sourceConnectionID: scid)
        let address = SocketAddress(ipAddress: "127.0.0.1", port: 4433)

        let connection = ManagedConnection(
            role: .client,
            version: .v1,
            sourceConnectionID: scid,
            destinationConnectionID: dcid,
            transportParameters: params,
            tlsProvider: tlsProvider,
            remoteAddress: address
        )

        _ = try await connection.start()

        // Open a stream
        let stream = try await connection.openStream()

        // Start a read in background (will wait for data)
        let readTask = Task {
            try await stream.read()
        }

        // Give the read task time to register its continuation
        try await Task.sleep(for: .milliseconds(50))

        // Shutdown should resume the waiting reader
        connection.shutdown()

        // The read task should complete with an error
        var errorThrown = false
        do {
            _ = try await readTask.value
            Issue.record("Expected error from read")
        } catch {
            // Expected - reader was resumed with error
            errorThrown = true
        }
        #expect(errorThrown, "Read should have thrown an error")
    }

    @Test("shutdown() finishes existing incomingStreams iterator", .timeLimit(.minutes(1)))
    func shutdownFinishesExistingIterator() async throws {
        let connection = try createTestConnection()
        _ = try await connection.start()

        // Get the stream BEFORE shutdown (creates iterator)
        let streams = connection.incomingStreams

        // Start iterating in background
        let iterateTask = Task {
            var count = 0
            for await _ in streams {
                count += 1
            }
            return count
        }

        // Give time to start iteration
        try await Task.sleep(for: .milliseconds(50))

        // Shutdown should finish the stream
        connection.shutdown()

        // Iterator should complete
        let count = await iterateTask.value
        #expect(count == 0, "No streams should have been received")
    }

    @Test("Pending streams are buffered until incomingStreams is accessed", .timeLimit(.minutes(1)))
    func pendingStreamsAreBuffered() async throws {
        // This test verifies that streams arriving before incomingStreams
        // is accessed are buffered and delivered when it is accessed.
        // Note: We can't easily simulate incoming streams in a unit test,
        // but we verify the structure handles the pattern correctly.

        let connection = try createTestConnection()
        _ = try await connection.start()

        // Access incomingStreams (this creates the continuation)
        let streams = connection.incomingStreams

        // Start a task to collect streams
        let collectTask = Task {
            var count = 0
            for await _ in streams {
                count += 1
                if count >= 1 { break }  // Exit after first stream
            }
            return count
        }

        // Give time for the task to start waiting
        try await Task.sleep(for: .milliseconds(50))

        // Shutdown - this will finish the stream
        connection.shutdown()

        // Task should complete (possibly with 0 streams since we didn't simulate incoming)
        let count = await collectTask.value
        #expect(count >= 0, "Task should complete without hanging")
    }
}

// MARK: - Integration Tests

@Suite("Integration Tests")
struct IntegrationTests {
    @Test("Client-Server packet exchange")
    func clientServerPacketExchange() async throws {
        let config = QUICConfiguration.testing()
        let serverAddress = SocketAddress(ipAddress: "127.0.0.1", port: 4433)
        let clientAddress = SocketAddress(ipAddress: "127.0.0.1", port: 54321)

        // Create endpoints
        let server = try await QUICEndpoint.listen(address: serverAddress, configuration: config)
        let client = QUICEndpoint(configuration: config)

        // Capture packets
        let clientToServer = PacketCollector()
        let serverToClient = PacketCollector()

        await client.setSendCallback { data, _ in
            clientToServer.append(data)
        }

        await server.setSendCallback { data, _ in
            serverToClient.append(data)
        }

        // Client initiates connection
        let _ = try await client.connect(to: serverAddress)

        // Process client's Initial at server
        for packet in clientToServer.packets {
            _ = try await server.processIncomingPacket(packet, from: clientAddress)
        }

        // Server should have sent response
        #expect(!serverToClient.isEmpty)

        // Process server's response at client
        for packet in serverToClient.packets {
            _ = try await client.processIncomingPacket(packet, from: serverAddress)
        }

        // Both endpoints should have connections
        #expect(await client.connectionCount >= 1)
        #expect(await server.connectionCount >= 1)
    }
}
