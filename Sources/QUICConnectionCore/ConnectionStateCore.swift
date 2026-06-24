/// Embedded-clean connection lifecycle state machine (RFC 9000 §10) as a value type.
///
/// This is the byte-identical lifecycle / packet-number bookkeeping of the host
/// `ConnectionState`, expressed as a `struct` with `mutating` transition methods and
/// deadline computations driven by injected `UInt64` nanosecond time. The host
/// `ConnectionState` is held inside the `QUICConnectionHandler`'s `Mutex`; it keeps the
/// same public surface (`status`, `getNextPacketNumber`, `updateLargestReceived`, the
/// per-level packet-number dictionaries) and forwards to this core, so observable
/// behavior is unchanged.
///
/// The per-level packet-number maps are stored here as a fixed 4-element array indexed
/// by `EncryptionLevel.rawValue` (0...3), which is numerically identical to the host's
/// `[EncryptionLevel: UInt64]` while staying Embedded-clean (no custom-Hashable
/// dictionaries). The adapter exposes the dictionary view for source compatibility.
///
/// Close / drain timing (RFC 9000 §10.2): once a connection enters the closing/draining
/// period it remains there for 3 * PTO. `drainDeadlineNanos(closeStartedNanos:ptoNanos:)`
/// computes that deadline as a value from injected time; the adapter owns the timer task
/// that fires it.
///
/// Embedded-clean: no Foundation, no `ContinuousClock`, no `any`, no `Mutex`.

import QUICWire

// MARK: - Connection Status

/// The lifecycle status of a QUIC connection.
public enum ConnectionStatusCore: Sendable, Hashable {
    /// Connection is being established (handshake in progress).
    case handshaking
    /// Connection is established and ready for use.
    case established
    /// Connection is being closed (draining period).
    case draining
    /// Connection is closed.
    case closed
}

// MARK: - Connection Role

/// The role of this endpoint in the connection.
public enum ConnectionRoleCore: Sendable {
    /// This endpoint initiated the connection (client).
    case client
    /// This endpoint accepted the connection (server).
    case server
}

// MARK: - Connection State Core

/// Internal lifecycle state for a QUIC connection.
public struct ConnectionStateCore: Sendable {

    /// Current connection status.
    public var status: ConnectionStatusCore

    /// This endpoint's role.
    public let role: ConnectionRoleCore

    /// QUIC version being used.
    public var version: QUICVersion

    /// Source connection IDs (ours).
    public var sourceConnectionIDs: [ConnectionID]

    /// Destination connection IDs (peer's).
    public var destinationConnectionIDs: [ConnectionID]

    /// Next packet number to send for each encryption level, indexed by rawValue.
    /// initial/handshake/application start at 0; zeroRTT starts at 0 on first use.
    private var nextPacketNumbers: [UInt64]

    /// Largest packet number received for each level, indexed by rawValue.
    /// `nil` until at least one packet is received at that level.
    private var largestReceivedPacketNumbers: [UInt64?]

    /// Current destination connection ID (first, or empty).
    public var currentDestinationCID: ConnectionID {
        destinationConnectionIDs.first ?? .empty
    }

    /// Current source connection ID (first, or empty).
    public var currentSourceCID: ConnectionID {
        sourceConnectionIDs.first ?? .empty
    }

    // MARK: - Initialization

    /// Creates initial connection state (status = handshaking; initial/handshake/
    /// application packet numbers seeded to 0, matching the host dictionary seed).
    public init(
        role: ConnectionRoleCore,
        version: QUICVersion,
        sourceConnectionID: ConnectionID,
        destinationConnectionID: ConnectionID
    ) {
        self.status = .handshaking
        self.role = role
        self.version = version
        self.sourceConnectionIDs = [sourceConnectionID]
        self.destinationConnectionIDs = [destinationConnectionID]
        // Host seeds initial/handshake/application to 0; zeroRTT is absent (defaults to
        // 0 on first read). A 4-element array of 0 is numerically identical because
        // getNextPacketNumber returns the stored value (0) before incrementing.
        self.nextPacketNumbers = [0, 0, 0, 0]
        self.largestReceivedPacketNumbers = [nil, nil, nil, nil]
    }

    // MARK: - Packet Number Bookkeeping

    /// Returns the next packet number for `level` and increments the counter.
    public mutating func getNextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        let index = level.rawValue
        let pn = nextPacketNumbers[index]
        nextPacketNumbers[index] = pn &+ 1
        return pn
    }

    /// Reads the next-to-send packet number for `level` without incrementing.
    public func nextPacketNumber(for level: EncryptionLevel) -> UInt64 {
        nextPacketNumbers[level.rawValue]
    }

    /// Updates the largest received packet number for `level` if `pn` is larger.
    public mutating func updateLargestReceived(_ pn: UInt64, level: EncryptionLevel) {
        let index = level.rawValue
        if let current = largestReceivedPacketNumbers[index] {
            if pn > current {
                largestReceivedPacketNumbers[index] = pn
            }
        } else {
            largestReceivedPacketNumbers[index] = pn
        }
    }

    /// Reads the largest received packet number for `level`, or `nil` if none.
    public func largestReceived(for level: EncryptionLevel) -> UInt64? {
        largestReceivedPacketNumbers[level.rawValue]
    }

    // MARK: - Lifecycle Transitions (RFC 9000 §10)

    /// Handshake confirmed (HANDSHAKE_DONE received, or server handshake complete):
    /// transition to `established`. No-op once draining/closed.
    public mutating func handshakeConfirmed() {
        guard status == .handshaking || status == .established else { return }
        status = .established
    }

    /// We initiated a close (sent CONNECTION_CLOSE): enter the draining period.
    /// No-op if already closed.
    public mutating func closeInitiated() {
        guard status != .closed else { return }
        status = .draining
    }

    /// We received a peer CONNECTION_CLOSE: enter the draining period.
    /// No-op if already closed.
    public mutating func closeReceived() {
        guard status != .closed else { return }
        status = .draining
    }

    /// The drain period elapsed (or hard close): the connection is closed.
    public mutating func markClosed() {
        status = .closed
    }

    // MARK: - Close / Drain Deadline (RFC 9000 §10.2)

    /// The drain-period deadline: a connection in the closing/draining state remains
    /// there for 3 * PTO (RFC 9000 §10.2). Computed from injected time as a value;
    /// the adapter owns the timer that fires `markClosed()` at this deadline.
    ///
    /// - Parameters:
    ///   - closeStartedNanos: When the close/drain period began (epoch-relative ns).
    ///   - ptoNanos: The current Probe Timeout in nanoseconds.
    /// - Returns: The deadline in epoch-relative nanoseconds (`closeStarted + 3 * PTO`).
    public func drainDeadlineNanos(closeStartedNanos: UInt64, ptoNanos: UInt64) -> UInt64 {
        closeStartedNanos &+ (ptoNanos &* 3)
    }
}
