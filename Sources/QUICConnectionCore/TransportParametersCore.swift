/// QUIC Transport Parameters value types — Embedded-clean core (RFC 9000 §18).
///
/// Byte fields use owned `[UInt8]` storage. The `preferred_address` IP fields
/// retain their network-order wire representation (`[UInt8]`: 4 for IPv4, 16
/// for IPv6); textual formatting is an application-boundary concern.
///
/// Embedded-clean: no Foundation, no `any`. The wire codec lives in
/// ``TransportParameterCodecCore``.

import QUICWire

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
    /// Whether this endpoint supports RESET_STREAM_AT (draft-ietf-quic-reliable-stream-reset-09).
    public var enableResetStreamAt: Bool
    public var maxDatagramFrameSize: UInt64

    /// Creates transport parameters with the RFC defaults used when a parameter
    /// is absent from the peer's TLS extension.
    ///
    /// Decoding starts from these defaults and overwrites only parameters that
    /// are present on the wire.
    public init() {
        self.originalDestinationConnectionID = nil
        self.maxIdleTimeout = 0
        self.statelessResetToken = nil
        self.maxUDPPayloadSize = 65527
        self.initialMaxData = 0
        self.initialMaxStreamDataBidiLocal = 0
        self.initialMaxStreamDataBidiRemote = 0
        self.initialMaxStreamDataUni = 0
        self.initialMaxStreamsBidi = 0
        self.initialMaxStreamsUni = 0
        self.ackDelayExponent = 3
        self.maxAckDelay = 25
        self.disableActiveMigration = false
        self.preferredAddress = nil
        self.activeConnectionIDLimit = 2
        self.initialSourceConnectionID = nil
        self.retrySourceConnectionID = nil
        self.enableResetStreamAt = false
        self.maxDatagramFrameSize = 0
    }

    /// Creates a practical local advertisement without changing the RFC defaults
    /// used by decoding. Applications remain free to tune every field before the
    /// value is passed to the engine configuration.
    public static func recommendedLocal() -> Self {
        var parameters = Self()
        parameters.maxIdleTimeout = 30_000
        parameters.initialMaxData = 10_000_000
        parameters.initialMaxStreamDataBidiLocal = 1_000_000
        parameters.initialMaxStreamDataBidiRemote = 1_000_000
        parameters.initialMaxStreamDataUni = 1_000_000
        parameters.initialMaxStreamsBidi = 100
        parameters.initialMaxStreamsUni = 100
        return parameters
    }
}
