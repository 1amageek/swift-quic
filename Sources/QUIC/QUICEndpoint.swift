/// QUIC Endpoint
///
/// Main entry point for QUIC connections.
/// Provides both client and server APIs.

import Foundation
import Synchronization
import QUICCore
import QUICCrypto
import QUICConnection

// MARK: - QUIC Endpoint

/// A QUIC endpoint that can act as client or server
///
/// Provides a unified API for:
/// - Client connections: `connect(to:)`
/// - Server listening: `listen()`
/// - Packet I/O and routing
/// - Timer management
///
/// ## Usage
///
/// ### Client
/// ```swift
/// let endpoint = QUICEndpoint(configuration: config)
/// let connection = try await endpoint.connect(to: serverAddress)
/// let stream = try await connection.openStream()
/// try await stream.write(data)
/// ```
///
/// ### Server
/// ```swift
/// let endpoint = try await QUICEndpoint.listen(
///     address: bindAddress,
///     configuration: config
/// )
/// for await connection in endpoint.incomingConnections {
///     // Handle connection
/// }
/// ```
public actor QUICEndpoint {
    // MARK: - Properties

    /// Configuration
    private let configuration: QUICConfiguration

    /// Connection router
    private let router: ConnectionRouter

    /// Timer manager
    private let timerManager: TimerManager

    /// Whether this endpoint is a server
    private let isServer: Bool

    /// Incoming connections (server mode)
    private var incomingConnectionContinuation: AsyncStream<any QUICConnectionProtocol>.Continuation?

    /// Send callback (for testing without real socket)
    private var sendCallback: (@Sendable (Data, SocketAddress) async throws -> Void)?

    /// Local address
    private var _localAddress: SocketAddress?

    /// Whether the endpoint is running
    private var isRunning: Bool = false

    // MARK: - Initialization

    /// Creates a client endpoint
    /// - Parameter configuration: QUIC configuration
    public init(configuration: QUICConfiguration) {
        self.configuration = configuration
        self.router = ConnectionRouter(isServer: false, dcidLength: 8)
        self.timerManager = TimerManager(idleTimeout: configuration.maxIdleTimeout)
        self.isServer = false
    }

    /// Creates a server endpoint (internal)
    private init(configuration: QUICConfiguration, isServer: Bool) {
        self.configuration = configuration
        self.router = ConnectionRouter(isServer: isServer, dcidLength: 8)
        self.timerManager = TimerManager(idleTimeout: configuration.maxIdleTimeout)
        self.isServer = isServer
    }

    // MARK: - Server API

    /// Creates a server endpoint listening on the specified address
    /// - Parameters:
    ///   - address: The address to bind to
    ///   - configuration: QUIC configuration
    /// - Returns: A listening endpoint
    public static func listen(
        address: SocketAddress,
        configuration: QUICConfiguration
    ) async throws -> QUICEndpoint {
        let endpoint = QUICEndpoint(configuration: configuration, isServer: true)
        await endpoint.setLocalAddress(address)
        return endpoint
    }

    /// Sets the local address (internal)
    private func setLocalAddress(_ address: SocketAddress) {
        _localAddress = address
    }

    /// The local address this endpoint is bound to
    public var localAddress: SocketAddress? {
        _localAddress
    }

    /// Stream of incoming connections (server mode)
    public var incomingConnections: AsyncStream<any QUICConnectionProtocol> {
        AsyncStream { continuation in
            self.incomingConnectionContinuation = continuation
        }
    }

    // MARK: - Client API

    /// Connects to a remote QUIC server
    /// - Parameter address: The server address
    /// - Returns: The established connection
    public func connect(to address: SocketAddress) async throws -> any QUICConnectionProtocol {
        guard !isServer else {
            throw QUICEndpointError.serverCannotConnect
        }

        // Generate connection IDs
        let sourceConnectionID = ConnectionID.random(length: 8)
        let destinationConnectionID = ConnectionID.random(length: 8)

        // Create TLS provider
        let tlsProvider = MockTLSProvider(configuration: TLSConfiguration())

        // Create transport parameters from configuration
        let transportParameters = TransportParameters(from: configuration, sourceConnectionID: sourceConnectionID)

        // Create connection
        let connection = ManagedConnection(
            role: .client,
            version: configuration.version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID,
            transportParameters: transportParameters,
            tlsProvider: tlsProvider,
            localAddress: _localAddress,
            remoteAddress: address
        )

        // Register connection
        router.register(connection)
        timerManager.register(connection)

        // Start handshake
        let initialPackets = try await connection.start()

        // Send initial packets
        for packet in initialPackets {
            try await send(packet, to: address)
        }

        // Wait for handshake completion (simplified - in real impl, use packet loop)
        // For now, return immediately and let the caller drive the packet loop

        return connection
    }

    // MARK: - Packet Processing

    /// Processes an incoming packet
    /// - Parameters:
    ///   - data: The packet data
    ///   - remoteAddress: Where the packet came from
    /// - Returns: Outbound packets to send
    public func processIncomingPacket(_ data: Data, from remoteAddress: SocketAddress) async throws -> [Data] {
        // Route the packet
        switch router.route(data: data, from: remoteAddress) {
        case .routed(let connection):
            // Process packet through the connection
            timerManager.recordActivity(for: connection)
            let responses = try await connection.processDatagram(data)

            // Send responses
            for response in responses {
                try await send(response, to: remoteAddress)
            }

            return responses

        case .newConnection(let info):
            // Server: Create new connection for Initial packet
            guard isServer else {
                throw QUICEndpointError.unexpectedPacket
            }

            let connection = try await handleNewConnection(info: info)
            let responses = try await connection.processDatagram(data)

            // Send responses
            for response in responses {
                try await send(response, to: remoteAddress)
            }

            return responses

        case .notFound(let dcid):
            throw QUICEndpointError.connectionNotFound(dcid)

        case .invalid(let error):
            throw error
        }
    }

    /// Handles a new incoming connection (server mode)
    private func handleNewConnection(info: ConnectionRouter.IncomingConnectionInfo) async throws -> ManagedConnection {
        // Generate our source connection ID
        let sourceConnectionID = ConnectionID.random(length: 8)

        // Create TLS provider
        let tlsProvider = MockTLSProvider(configuration: TLSConfiguration())

        // Create transport parameters from configuration
        let transportParameters = TransportParameters(from: configuration, sourceConnectionID: sourceConnectionID)

        // Create connection
        // For servers:
        // - sourceConnectionID: Our randomly chosen SCID
        // - destinationConnectionID: Client's SCID (for future packets to the client)
        // - originalConnectionID: DCID from client's Initial (for Initial key derivation)
        let connection = ManagedConnection(
            role: .server,
            version: configuration.version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: info.sourceConnectionID,
            originalConnectionID: info.destinationConnectionID,
            transportParameters: transportParameters,
            tlsProvider: tlsProvider,
            localAddress: _localAddress,
            remoteAddress: info.remoteAddress
        )

        // Register with both our SCID and the client's DCID
        router.register(connection, for: [
            sourceConnectionID,
            info.destinationConnectionID
        ])
        timerManager.register(connection)

        // Start handshake (server doesn't send first)
        _ = try await connection.start()

        // Notify about new connection
        incomingConnectionContinuation?.yield(connection)

        return connection
    }

    // MARK: - Timer Processing

    /// Processes expired timers
    /// - Returns: Any packets that need to be sent
    public func processTimers() async throws -> [(Data, SocketAddress)] {
        var outbound: [(Data, SocketAddress)] = []

        let events = timerManager.processTimers()
        for event in events {
            switch event {
            case .sendAck(let connection), .lossDetection(let connection), .probe(let connection):
                let packets = try connection.onTimerExpired()
                for packet in packets {
                    outbound.append((packet, connection.remoteAddress))
                }

            case .idleTimeout(let connection):
                // Close connection due to idle timeout
                await connection.close(error: nil)
                router.unregister(connection)
                timerManager.markClosed(connection)
            }
        }

        return outbound
    }

    /// Gets the next timer deadline
    public func nextTimerDeadline() -> ContinuousClock.Instant? {
        timerManager.nextDeadline()
    }

    // MARK: - Event Loop

    /// Runs the main event loop (for testing)
    /// Call this with incoming packets and it will process them
    public func runOnce(
        incoming: [(data: Data, address: SocketAddress)]
    ) async throws -> [(data: Data, address: SocketAddress)] {
        var outgoing: [(data: Data, address: SocketAddress)] = []

        // Process incoming packets
        for (data, address) in incoming {
            do {
                let responses = try await processIncomingPacket(data, from: address)
                for response in responses {
                    outgoing.append((response, address))
                }
            } catch {
                // Log error but continue processing
                print("Error processing packet: \(error)")
            }
        }

        // Process timers
        let timerPackets = try await processTimers()
        outgoing.append(contentsOf: timerPackets)

        return outgoing
    }

    // MARK: - Send Callback

    /// Sets a callback for sending packets (for testing)
    public func setSendCallback(_ callback: @escaping @Sendable (Data, SocketAddress) async throws -> Void) {
        sendCallback = callback
    }

    /// Sends a packet
    private func send(_ data: Data, to address: SocketAddress) async throws {
        if let callback = sendCallback {
            try await callback(data, address)
        }
        // If no callback, packets are silently dropped (useful for unit testing)
    }

    // MARK: - Connection Management

    /// Closes all connections
    public func closeAll() async {
        for connection in router.allConnections {
            await connection.close(error: nil)
            timerManager.markClosed(connection)
        }
    }

    /// Number of active connections
    public var connectionCount: Int {
        router.connectionCount
    }

    /// Gets a connection by its ID
    public func connection(for connectionID: ConnectionID) -> ManagedConnection? {
        router.connection(for: connectionID)
    }
}

// MARK: - Errors

/// Errors from QUICEndpoint
public enum QUICEndpointError: Error, Sendable {
    /// Server endpoint cannot initiate connections
    case serverCannotConnect

    /// Connection not found for the given DCID
    case connectionNotFound(ConnectionID)

    /// Unexpected packet received
    case unexpectedPacket

    /// Endpoint is already running
    case alreadyRunning

    /// Endpoint is not running
    case notRunning
}
