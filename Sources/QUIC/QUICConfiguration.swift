/// QUIC Configuration
///
/// Configuration options for QUIC connections.

import Foundation
import QUICCore

// MARK: - QUIC Configuration

/// Configuration for a QUIC endpoint
public struct QUICConfiguration: Sendable {
    // MARK: - Connection Settings

    /// Maximum idle timeout (default: 30 seconds)
    public var maxIdleTimeout: Duration

    /// Maximum UDP payload size (default: 1200)
    public var maxUDPPayloadSize: Int

    // MARK: - Flow Control

    /// Initial maximum data the peer can send on the connection (default: 10 MB)
    public var initialMaxData: UInt64

    /// Initial max data for locally-initiated bidirectional streams (default: 1 MB)
    public var initialMaxStreamDataBidiLocal: UInt64

    /// Initial max data for remotely-initiated bidirectional streams (default: 1 MB)
    public var initialMaxStreamDataBidiRemote: UInt64

    /// Initial max data for unidirectional streams (default: 1 MB)
    public var initialMaxStreamDataUni: UInt64

    /// Initial max bidirectional streams (default: 100)
    public var initialMaxStreamsBidi: UInt64

    /// Initial max unidirectional streams (default: 100)
    public var initialMaxStreamsUni: UInt64

    // MARK: - ACK Delay

    /// Maximum ack delay in milliseconds (default: 25ms)
    public var maxAckDelay: Duration

    /// ACK delay exponent (default: 3)
    public var ackDelayExponent: UInt64

    // MARK: - Connection ID

    /// Preferred connection ID length (default: 8)
    public var connectionIDLength: Int

    // MARK: - ALPN

    /// Application Layer Protocol Negotiation protocols
    public var alpn: [String]

    // MARK: - TLS

    /// Path to certificate file (for servers)
    public var certificatePath: String?

    /// Path to private key file (for servers)
    public var privateKeyPath: String?

    /// Whether to verify peer certificates (default: true)
    public var verifyPeer: Bool

    // MARK: - Initialization

    /// Creates a default configuration
    public init() {
        self.maxIdleTimeout = .seconds(30)
        self.maxUDPPayloadSize = 1200
        self.initialMaxData = 10_000_000
        self.initialMaxStreamDataBidiLocal = 1_000_000
        self.initialMaxStreamDataBidiRemote = 1_000_000
        self.initialMaxStreamDataUni = 1_000_000
        self.initialMaxStreamsBidi = 100
        self.initialMaxStreamsUni = 100
        self.maxAckDelay = .milliseconds(25)
        self.ackDelayExponent = 3
        self.connectionIDLength = 8
        self.alpn = ["h3"]
        self.certificatePath = nil
        self.privateKeyPath = nil
        self.verifyPeer = true
    }

    /// Creates a configuration for libp2p
    public static func libp2p() -> QUICConfiguration {
        var config = QUICConfiguration()
        config.alpn = ["libp2p"]
        return config
    }
}

// MARK: - Transport Parameters

/// QUIC Transport Parameters (RFC 9000 Section 18)
public struct TransportParameters: Sendable, Hashable {
    public var originalDestinationConnectionID: ConnectionID?
    public var maxIdleTimeout: UInt64
    public var statelessResetToken: Data?
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
    public var preferredAddress: PreferredAddress?
    public var activeConnectionIDLimit: UInt64
    public var initialSourceConnectionID: ConnectionID?
    public var retrySourceConnectionID: ConnectionID?

    public init() {
        self.originalDestinationConnectionID = nil
        self.maxIdleTimeout = 30_000  // 30 seconds in ms
        self.statelessResetToken = nil
        self.maxUDPPayloadSize = 65527
        self.initialMaxData = 10_000_000
        self.initialMaxStreamDataBidiLocal = 1_000_000
        self.initialMaxStreamDataBidiRemote = 1_000_000
        self.initialMaxStreamDataUni = 1_000_000
        self.initialMaxStreamsBidi = 100
        self.initialMaxStreamsUni = 100
        self.ackDelayExponent = 3
        self.maxAckDelay = 25  // 25 ms
        self.disableActiveMigration = false
        self.preferredAddress = nil
        self.activeConnectionIDLimit = 2
        self.initialSourceConnectionID = nil
        self.retrySourceConnectionID = nil
    }

    /// Creates transport parameters from a configuration
    public init(from config: QUICConfiguration, sourceConnectionID: ConnectionID) {
        self.init()
        self.maxIdleTimeout = UInt64(config.maxIdleTimeout.components.seconds * 1000)
        self.maxUDPPayloadSize = UInt64(config.maxUDPPayloadSize)
        self.initialMaxData = config.initialMaxData
        self.initialMaxStreamDataBidiLocal = config.initialMaxStreamDataBidiLocal
        self.initialMaxStreamDataBidiRemote = config.initialMaxStreamDataBidiRemote
        self.initialMaxStreamDataUni = config.initialMaxStreamDataUni
        self.initialMaxStreamsBidi = config.initialMaxStreamsBidi
        self.initialMaxStreamsUni = config.initialMaxStreamsUni
        self.ackDelayExponent = config.ackDelayExponent
        self.maxAckDelay = UInt64(config.maxAckDelay.components.seconds * 1000 +
                                   config.maxAckDelay.components.attoseconds / 1_000_000_000_000_000)
        self.initialSourceConnectionID = sourceConnectionID
    }
}

/// Preferred address for connection migration
public struct PreferredAddress: Sendable, Hashable {
    public var ipv4Address: String?
    public var ipv4Port: UInt16?
    public var ipv6Address: String?
    public var ipv6Port: UInt16?
    public var connectionID: ConnectionID
    public var statelessResetToken: Data

    public init(
        ipv4Address: String? = nil,
        ipv4Port: UInt16? = nil,
        ipv6Address: String? = nil,
        ipv6Port: UInt16? = nil,
        connectionID: ConnectionID,
        statelessResetToken: Data
    ) {
        self.ipv4Address = ipv4Address
        self.ipv4Port = ipv4Port
        self.ipv6Address = ipv6Address
        self.ipv6Port = ipv6Port
        self.connectionID = connectionID
        self.statelessResetToken = statelessResetToken
    }
}
