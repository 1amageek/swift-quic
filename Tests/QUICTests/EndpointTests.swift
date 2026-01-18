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
        let config = QUICConfiguration()
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
        let config = QUICConfiguration()
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
        let dcid = ConnectionID.random(length: 8)
        let scid = ConnectionID.random(length: 8)

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
        let scid = ConnectionID.random(length: 8)
        let dcid = ConnectionID.random(length: 8)
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
        let scid = ConnectionID.random(length: 8)
        let dcid = ConnectionID.random(length: 8)
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
        let scid = ConnectionID.random(length: 8)
        let dcid = ConnectionID.random(length: 8)
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
        let scid = ConnectionID.random(length: 8)
        let dcid = ConnectionID.random(length: 8)
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
        let scid = ConnectionID.random(length: 8)
        let dcid = ConnectionID.random(length: 8)
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
        let dcid = ConnectionID.random(length: 8)
        let scid = ConnectionID.random(length: 8)

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

// MARK: - Integration Tests

@Suite("Integration Tests")
struct IntegrationTests {
    @Test("Client-Server packet exchange")
    func clientServerPacketExchange() async throws {
        let config = QUICConfiguration()
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
