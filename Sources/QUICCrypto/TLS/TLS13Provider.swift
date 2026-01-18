/// TLS 1.3 Provider Protocol (RFC 9001)
///
/// Abstraction for TLS 1.3 implementation used in QUIC.
/// Allows swapping between different TLS backends (BoringSSL, etc.)
/// and mocking for tests.

import Foundation
import QUICCore

// MARK: - TLS 1.3 Provider Protocol

/// Protocol for TLS 1.3 implementations used with QUIC
///
/// QUIC uses TLS 1.3 for key agreement and authentication, but with
/// a modified record layer. The TLS handshake messages are carried
/// in CRYPTO frames, and the record layer encryption is replaced
/// with QUIC packet protection.
///
/// Implementations should:
/// - Handle TLS 1.3 handshake state machine
/// - Export secrets at each encryption level
/// - Support QUIC transport parameters extension (0x0039)
/// - Never send TLS alerts directly (return as errors)
public protocol TLS13Provider: Sendable {
    /// Starts the TLS handshake
    ///
    /// For clients, this generates the ClientHello message.
    /// For servers, this prepares to receive ClientHello.
    ///
    /// - Parameter isClient: true for client mode, false for server mode
    /// - Returns: Initial TLS output (typically ClientHello data for clients)
    func startHandshake(isClient: Bool) async throws -> [TLSOutput]

    /// Processes incoming TLS handshake data
    ///
    /// - Parameters:
    ///   - data: Received TLS handshake data
    ///   - level: The encryption level at which the data was received
    /// - Returns: Array of TLS outputs (may include data to send, keys, completion)
    func processHandshakeData(_ data: Data, at level: EncryptionLevel) async throws -> [TLSOutput]

    /// Gets the local transport parameters to be sent in the TLS extension
    ///
    /// Must be called before starting the handshake to include in ClientHello/EncryptedExtensions.
    ///
    /// - Returns: Encoded transport parameters
    func getLocalTransportParameters() -> Data

    /// Sets the local transport parameters
    ///
    /// - Parameter params: Encoded transport parameters to send
    func setLocalTransportParameters(_ params: Data) throws

    /// Gets the peer's transport parameters received in the TLS extension
    ///
    /// Available after processing ServerHello (client) or ClientHello (server).
    ///
    /// - Returns: Encoded transport parameters, or nil if not yet received
    func getPeerTransportParameters() -> Data?

    /// Whether the handshake is complete
    var isHandshakeComplete: Bool { get }

    /// Whether this is acting as a client
    var isClient: Bool { get }

    /// The negotiated ALPN protocol (if any)
    var negotiatedALPN: String? { get }

    /// Write a key update request
    ///
    /// Initiates a TLS KeyUpdate handshake message.
    /// This is used for 1-RTT key rotation.
    ///
    /// - Returns: TLS outputs for the key update
    func requestKeyUpdate() async throws -> [TLSOutput]

    /// Export keying material (RFC 5705 / RFC 8446 Section 7.5)
    ///
    /// - Parameters:
    ///   - label: The label for the export
    ///   - context: Optional context data
    ///   - length: Desired output length
    /// - Returns: Exported keying material
    func exportKeyingMaterial(
        label: String,
        context: Data?,
        length: Int
    ) throws -> Data
}

// MARK: - TLS Configuration

/// Configuration for TLS 1.3 provider
public struct TLSConfiguration: Sendable {
    /// Application Layer Protocol Negotiation protocols (in preference order)
    public var alpnProtocols: [String]

    /// Path to certificate file (PEM format) - for servers
    public var certificatePath: String?

    /// Path to private key file (PEM format) - for servers
    public var privateKeyPath: String?

    /// Certificate chain (DER encoded) - alternative to file path
    public var certificateChain: [Data]?

    /// Private key (DER encoded) - alternative to file path
    public var privateKey: Data?

    /// Whether to verify peer certificates (default: true)
    public var verifyPeer: Bool

    /// Trusted CA certificates for peer verification (DER encoded)
    public var trustedCACertificates: [Data]?

    /// Server name for SNI (client only)
    public var serverName: String?

    /// Session ticket for resumption (client only)
    public var sessionTicket: Data?

    /// Maximum early data size for 0-RTT (0 to disable)
    public var maxEarlyDataSize: UInt32

    /// Creates a default configuration
    public init() {
        self.alpnProtocols = ["h3"]
        self.certificatePath = nil
        self.privateKeyPath = nil
        self.certificateChain = nil
        self.privateKey = nil
        self.verifyPeer = true
        self.trustedCACertificates = nil
        self.serverName = nil
        self.sessionTicket = nil
        self.maxEarlyDataSize = 0
    }

    /// Creates a client configuration
    public static func client(
        serverName: String? = nil,
        alpnProtocols: [String] = ["h3"]
    ) -> TLSConfiguration {
        var config = TLSConfiguration()
        config.serverName = serverName
        config.alpnProtocols = alpnProtocols
        return config
    }

    /// Creates a server configuration
    public static func server(
        certificatePath: String,
        privateKeyPath: String,
        alpnProtocols: [String] = ["h3"]
    ) -> TLSConfiguration {
        var config = TLSConfiguration()
        config.certificatePath = certificatePath
        config.privateKeyPath = privateKeyPath
        config.alpnProtocols = alpnProtocols
        return config
    }

    /// Creates a configuration for libp2p
    public static func libp2p(serverName: String? = nil) -> TLSConfiguration {
        var config = TLSConfiguration()
        config.serverName = serverName
        config.alpnProtocols = ["libp2p"]
        return config
    }
}
