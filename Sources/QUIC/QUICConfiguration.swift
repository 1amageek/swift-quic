/// QUIC Configuration
///
/// Configuration options for QUIC connections.

import Foundation
import QUICCore
import QUICCrypto

// MARK: - TLS Provider Factory

/// Factory for creating TLS 1.3 providers.
///
/// This allows custom TLS implementations (like libp2p's TLS with
/// X.509 certificate extensions) to be injected into QUIC connections.
///
/// ## Example
///
/// ```swift
/// var config = QUICConfiguration()
/// config.tlsProviderFactory = { isClient in
///     MyCustomTLSProvider(isClient: isClient)
/// }
/// ```
public typealias TLSProviderFactory = @Sendable (_ isClient: Bool) -> any TLS13Provider

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

    // MARK: - Version

    /// QUIC version to use
    public var version: QUICVersion

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

    /// Custom TLS provider factory.
    ///
    /// When set, this factory is used to create TLS providers for new connections
    /// instead of the default MockTLSProvider. This enables custom TLS
    /// implementations like libp2p's certificate-based peer authentication.
    ///
    /// - Parameter isClient: `true` for client connections, `false` for server connections
    /// - Returns: A TLS 1.3 provider instance
    public var tlsProviderFactory: TLSProviderFactory?

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
        self.version = .v1
        self.alpn = ["h3"]
        self.certificatePath = nil
        self.privateKeyPath = nil
        self.verifyPeer = true
        self.tlsProviderFactory = nil
    }

    /// Creates a configuration for libp2p
    public static func libp2p() -> QUICConfiguration {
        var config = QUICConfiguration()
        config.alpn = ["libp2p"]
        return config
    }

    /// Creates a configuration for libp2p with a custom TLS provider factory.
    ///
    /// Use this when implementing libp2p TLS certificate authentication,
    /// where PeerID is embedded in X.509 certificate extensions.
    ///
    /// - Parameter tlsProviderFactory: Factory that creates TLS providers with libp2p certificate support
    /// - Returns: A configuration ready for libp2p QUIC connections
    public static func libp2p(tlsProviderFactory: @escaping TLSProviderFactory) -> QUICConfiguration {
        var config = QUICConfiguration()
        config.alpn = ["libp2p"]
        config.tlsProviderFactory = tlsProviderFactory
        return config
    }
}

// MARK: - Transport Parameters Extension

extension TransportParameters {
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
