/// QUIC Transport Parameters value types — Embedded-clean core (RFC 9000 §18).
///
/// `TransportParametersCore` mirrors the host adapter's `TransportParameters`
/// but stores byte fields as `[UInt8]` instead of `Data`, and the
/// `preferred_address` IP fields as their wire bytes (`[UInt8]`: 4 for IPv4, 16
/// for IPv6) rather than textual strings. The adapter converts at the boundary
/// (String <-> bytes via `IPAddressCodec`, `Data` <-> `[UInt8]`) so its public
/// `TransportParameters` API and the existing tests stay unchanged.
///
/// Embedded-clean: no Foundation, no `any`. The wire codec lives in
/// ``TransportParameterCodecCore``.

import QUICCoreCodec

/// Preferred address for connection migration (RFC 9000 §18.2), wire-byte form.
public struct PreferredAddressCore: Sendable, Hashable {
    /// IPv4 address as its 4 network-order bytes, or `nil` when not offered.
    public var ipv4Address: [UInt8]?

    /// IPv4 port (host byte order), or `nil` when not offered.
    public var ipv4Port: UInt16?

    /// IPv6 address as its 16 network-order bytes, or `nil` when not offered.
    public var ipv6Address: [UInt8]?

    /// IPv6 port (host byte order), or `nil` when not offered.
    public var ipv6Port: UInt16?

    /// Connection ID for the preferred address.
    public var connectionID: ConnectionID

    /// Stateless reset token for the preferred address (16 bytes).
    public var statelessResetToken: [UInt8]

    public init(
        ipv4Address: [UInt8]? = nil,
        ipv4Port: UInt16? = nil,
        ipv6Address: [UInt8]? = nil,
        ipv6Port: UInt16? = nil,
        connectionID: ConnectionID,
        statelessResetToken: [UInt8]
    ) {
        self.ipv4Address = ipv4Address
        self.ipv4Port = ipv4Port
        self.ipv6Address = ipv6Address
        self.ipv6Port = ipv6Port
        self.connectionID = connectionID
        self.statelessResetToken = statelessResetToken
    }
}

/// QUIC Transport Parameters exchanged during handshake, wire-byte form.
public struct TransportParametersCore: Sendable, Hashable {
    public var originalDestinationConnectionID: ConnectionID?
    public var maxIdleTimeout: UInt64
    public var statelessResetToken: [UInt8]?
    public var maxUDPPayloadSize: UInt64
    public var initialMaxData: UInt64
    public var initialMaxStreamDataBidiLocal: UInt64
    public var initialMaxStreamDataBidiRemote: UInt64
    public var initialMaxStreamDataUni: UInt64
    public var initialMaxStreamsBidi: UInt64
    public var initialMaxStreamsUni: UInt64
    public var ackDelayExponent: UInt64
    public var maxAckDelay: UInt64
    public var disableActiveMigration: Bool
    public var preferredAddress: PreferredAddressCore?
    public var activeConnectionIDLimit: UInt64
    public var initialSourceConnectionID: ConnectionID?
    public var retrySourceConnectionID: ConnectionID?
    public var maxDatagramFrameSize: UInt64

    /// Creates transport parameters with the protocol default values.
    ///
    /// These defaults match the host adapter's `TransportParameters.init()` so
    /// that decoding (which starts from defaults and overwrites only present
    /// parameters) produces identical absent-parameter values.
    public init() {
        self.originalDestinationConnectionID = nil
        self.maxIdleTimeout = 30_000
        self.statelessResetToken = nil
        self.maxUDPPayloadSize = 65527
        self.initialMaxData = 10_000_000
        self.initialMaxStreamDataBidiLocal = 1_000_000
        self.initialMaxStreamDataBidiRemote = 1_000_000
        self.initialMaxStreamDataUni = 1_000_000
        self.initialMaxStreamsBidi = 100
        self.initialMaxStreamsUni = 100
        self.ackDelayExponent = 3
        self.maxAckDelay = 25
        self.disableActiveMigration = false
        self.preferredAddress = nil
        self.activeConnectionIDLimit = 2
        self.initialSourceConnectionID = nil
        self.retrySourceConnectionID = nil
        self.maxDatagramFrameSize = 0
    }
}
