/// Connection Router
///
/// Routes incoming packets to the appropriate connection based on
/// Destination Connection ID (DCID).

import Foundation
import Synchronization
import QUICCore

// MARK: - Connection Router

/// Routes packets to connections based on DCID
///
/// Maintains a mapping of connection IDs to connections and handles:
/// - Known connection routing (by DCID)
/// - New connection creation (for Initial packets to server)
/// - Connection ID retirement and rotation
public final class ConnectionRouter: Sendable {
    // MARK: - Types

    /// Result of routing a packet
    public enum RouteResult: Sendable {
        /// Packet routed to existing connection
        case routed(ManagedConnection)

        /// New connection should be created (Initial packet to server)
        case newConnection(IncomingConnectionInfo)

        /// Connection not found and cannot create new
        case notFound(ConnectionID)

        /// Invalid packet (cannot extract DCID)
        case invalid(Error)
    }

    /// Information about an incoming connection request
    public struct IncomingConnectionInfo: Sendable {
        /// The destination connection ID from the packet
        public let destinationConnectionID: ConnectionID

        /// The source connection ID from the packet (client's chosen ID)
        public let sourceConnectionID: ConnectionID

        /// The packet type
        public let packetType: PacketType

        /// Remote address
        public let remoteAddress: SocketAddress

        /// The raw packet data
        public let data: Data
    }

    // MARK: - Properties

    /// Connection ID to connection mapping
    private let connections: Mutex<[ConnectionID: ManagedConnection]>

    /// Whether this is a server (can accept new connections)
    private let isServer: Bool

    /// Packet processor for DCID extraction
    private let packetProcessor: PacketProcessor

    // MARK: - Initialization

    /// Creates a connection router
    /// - Parameters:
    ///   - isServer: Whether this router is for a server endpoint
    ///   - dcidLength: Expected DCID length for short headers
    public init(isServer: Bool, dcidLength: Int = 8) {
        self.connections = Mutex([:])
        self.isServer = isServer
        self.packetProcessor = PacketProcessor(dcidLength: dcidLength)
    }

    // MARK: - Routing

    /// Routes a packet to the appropriate connection
    /// - Parameters:
    ///   - data: The packet data
    ///   - remoteAddress: Where the packet came from
    /// - Returns: The routing result
    public func route(data: Data, from remoteAddress: SocketAddress) -> RouteResult {
        // Extract DCID from packet
        let dcid: ConnectionID
        let packetType: PacketType
        let scid: ConnectionID?

        do {
            dcid = try packetProcessor.extractDestinationConnectionID(from: data)
            packetType = try packetProcessor.extractPacketType(from: data)

            // For Initial packets, also extract source CID
            if packetType == .initial {
                scid = try extractSourceConnectionID(from: data)
            } else {
                scid = nil
            }
        } catch {
            return .invalid(error)
        }

        // Look up connection by DCID
        if let connection = connections.withLock({ $0[dcid] }) {
            return .routed(connection)
        }

        // No existing connection found
        // For servers, Initial packets create new connections
        if isServer && packetType == .initial {
            return .newConnection(IncomingConnectionInfo(
                destinationConnectionID: dcid,
                sourceConnectionID: scid ?? ConnectionID.random(length: 8),
                packetType: packetType,
                remoteAddress: remoteAddress,
                data: data
            ))
        }

        return .notFound(dcid)
    }

    // MARK: - Connection Management

    /// Registers a connection with its connection IDs
    /// - Parameters:
    ///   - connection: The connection to register
    ///   - connectionIDs: The connection IDs to associate with this connection
    public func register(_ connection: ManagedConnection, for connectionIDs: [ConnectionID]) {
        connections.withLock { conns in
            for cid in connectionIDs {
                conns[cid] = connection
            }
        }
    }

    /// Registers a connection with its source connection ID
    /// - Parameter connection: The connection to register
    public func register(_ connection: ManagedConnection) {
        let scid = connection.sourceConnectionID
        connections.withLock { $0[scid] = connection }
    }

    /// Unregisters a connection
    /// - Parameter connection: The connection to unregister
    public func unregister(_ connection: ManagedConnection) {
        let scid = connection.sourceConnectionID
        _ = connections.withLock { conns in
            conns.removeValue(forKey: scid)
        }
    }

    /// Unregisters specific connection IDs
    /// - Parameter connectionIDs: The IDs to unregister
    public func unregister(connectionIDs: [ConnectionID]) {
        connections.withLock { conns in
            for cid in connectionIDs {
                conns.removeValue(forKey: cid)
            }
        }
    }

    /// Adds a new connection ID for an existing connection
    /// - Parameters:
    ///   - connectionID: The new connection ID
    ///   - connection: The connection to associate
    public func addConnectionID(_ connectionID: ConnectionID, for connection: ManagedConnection) {
        connections.withLock { $0[connectionID] = connection }
    }

    /// Retires a connection ID
    /// - Parameter connectionID: The ID to retire
    public func retireConnectionID(_ connectionID: ConnectionID) {
        _ = connections.withLock { $0.removeValue(forKey: connectionID) }
    }

    /// Gets a connection by its ID
    /// - Parameter connectionID: The connection ID
    /// - Returns: The connection, if found
    public func connection(for connectionID: ConnectionID) -> ManagedConnection? {
        connections.withLock { $0[connectionID] }
    }

    /// Gets all active connections
    public var allConnections: [ManagedConnection] {
        connections.withLock { Array(Set($0.values)) }
    }

    /// Number of registered connection IDs
    public var connectionIDCount: Int {
        connections.withLock { $0.count }
    }

    /// Number of unique connections
    public var connectionCount: Int {
        connections.withLock { Set($0.values).count }
    }

    // MARK: - Private Helpers

    /// Extracts source connection ID from an Initial packet
    private func extractSourceConnectionID(from data: Data) throws -> ConnectionID {
        // Parse the long header to get SCID
        // RFC 9000: Long header format
        // 1 byte: header form + type
        // 4 bytes: version
        // 1 byte: DCID length
        // N bytes: DCID
        // 1 byte: SCID length
        // M bytes: SCID

        guard data.count >= 7 else {
            throw PacketCodecError.insufficientData
        }

        let startIndex = data.startIndex

        // Skip header byte (1) + version (4)
        var offset = startIndex + 5

        // DCID length
        let dcidLen = Int(data[offset])
        offset += 1

        // Skip DCID
        offset += dcidLen

        guard offset < data.endIndex else {
            throw PacketCodecError.insufficientData
        }

        // SCID length
        let scidLen = Int(data[offset])
        offset += 1

        guard offset + scidLen <= data.endIndex else {
            throw PacketCodecError.insufficientData
        }

        // SCID
        let scidBytes = data[offset..<(offset + scidLen)]
        return ConnectionID(bytes: Data(scidBytes))
    }
}

// MARK: - Hashable for ManagedConnection

extension ManagedConnection: Hashable {
    public static func == (lhs: ManagedConnection, rhs: ManagedConnection) -> Bool {
        lhs.sourceConnectionID == rhs.sourceConnectionID
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(sourceConnectionID)
    }
}
