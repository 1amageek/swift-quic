/// QUIC Connection State Machine
///
/// Manages the lifecycle of a QUIC connection.
///
/// This is the host adapter over the Embedded-clean value type
/// `QUICConnectionCore.ConnectionStateCore`. The handler holds this `struct` inside
/// its `Mutex`; the FSM transitions and packet-number bookkeeping live in the core,
/// and this adapter forwards to it while preserving the prior public surface
/// (`status`, `getNextPacketNumber`, `updateLargestReceived`, the per-level
/// packet-number dictionary views). Observable behavior is unchanged.

import QUICCore
import QUICConnectionCore

// MARK: - Connection Status / Role

/// The status of a QUIC connection (re-exported from the Embedded-clean core).
public typealias ConnectionStatus = ConnectionStatusCore

/// The role of this endpoint in the connection (re-exported from the core).
public typealias ConnectionRole = ConnectionRoleCore

// MARK: - Connection State

/// Internal state for a QUIC connection.
///
/// A thin value-type wrapper around `ConnectionStateCore` that preserves the
/// dictionary-typed packet-number views used by existing callers.
public struct ConnectionState: Sendable {
    /// The Embedded-clean lifecycle / packet-number core.
    private var core: ConnectionStateCore

    /// Current connection status.
    public var status: ConnectionStatus {
        get { core.status }
        set { core.status = newValue }
    }

    /// This endpoint's role.
    public var role: ConnectionRole { core.role }

    /// QUIC version being used.
    public var version: QUICVersion {
        get { core.version }
        set { core.version = newValue }
    }

    /// Source connection IDs (ours).
    public var sourceConnectionIDs: [ConnectionID] {
        get { core.sourceConnectionIDs }
        set { core.sourceConnectionIDs = newValue }
    }

    /// Destination connection IDs (peer's).
    public var destinationConnectionIDs: [ConnectionID] {
        get { core.destinationConnectionIDs }
        set { core.destinationConnectionIDs = newValue }
    }

    /// Current destination connection ID.
    public var currentDestinationCID: ConnectionID { core.currentDestinationCID }

    /// Current source connection ID.
    public var currentSourceCID: ConnectionID { core.currentSourceCID }

    /// Next packet number to send for each encryption level.
    /// Backed by the core's per-level counters; seeded for the levels the host seeded.
    public var nextPacketNumber: [EncryptionLevel: UInt64] {
        [
            .initial: core.nextPacketNumber(for: .initial),
            .handshake: core.nextPacketNumber(for: .handshake),
            .application: core.nextPacketNumber(for: .application),
        ]
    }

    /// Largest packet number received for each encryption level.
    public var largestReceivedPacketNumber: [EncryptionLevel: UInt64] {
        var result: [EncryptionLevel: UInt64] = [:]
        for level in EncryptionLevel.allCases {
            if let pn = core.largestReceived(for: level) {
                result[level] = pn
            }
        }
        return result
    }

    /// Creates initial connection state.
    public init(
        role: ConnectionRole,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID
    ) {
        self.core = ConnectionStateCore(
            role: role,
            version: version,
            sourceConnectionID: sourceConnectionID,
            destinationConnectionID: destinationConnectionID
        )
    }

    /// Gets the next packet number for the given level and increments it.
    public mutating func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        core.getNextPacketNumber(for: level)
    }

    /// Updates the largest received packet number if the new one is larger.
    public mutating func updateLargestReceived(_ pn: UInt64, level: EncryptionLevel) {
        core.updateLargestReceived(pn, level: level)
    }
}
