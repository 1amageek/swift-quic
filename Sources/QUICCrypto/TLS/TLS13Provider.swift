/// QUIC's transport-facing TLS contract.
///
/// QUIC owns CRYPTO stream offsets, message reassembly, packet protection and
/// transport parameters. The TLS 1.3 protocol state machine is owned by
/// `swift-tls` and ultimately `swift-ssl`; this module only defines the
/// narrow adapter contract used by the QUIC host orchestrator.

import Foundation
import QUICCore
import TLSWireCore

// MARK: - Session resumption value

/// Opaque resumption input owned by a TLS implementation.
///
/// `swift-ssl` currently requires resumption to be supplied while constructing
/// its role-bound session. QUIC keeps this value type at the adapter boundary so
/// it can reject late configuration explicitly instead of silently ignoring a
/// ticket.
public struct SessionTicketData: Sendable, Hashable {
    public let ticket: Data
    public let resumptionPSK: Data
    public let maxEarlyDataSize: UInt32
    public let ticketAgeAdd: UInt32
    public let receiveTime: Date
    public let lifetime: UInt32
    public let serverName: String?
    public let alpn: String?

    public init(
        ticket: Data,
        resumptionPSK: Data,
        maxEarlyDataSize: UInt32 = 0,
        ticketAgeAdd: UInt32 = 0,
        receiveTime: Date = Date(),
        lifetime: UInt32 = 0,
        serverName: String? = nil,
        alpn: String? = nil
    ) {
        self.ticket = ticket
        self.resumptionPSK = resumptionPSK
        self.maxEarlyDataSize = maxEarlyDataSize
        self.ticketAgeAdd = ticketAgeAdd
        self.receiveTime = receiveTime
        self.lifetime = lifetime
        self.serverName = serverName
        self.alpn = alpn
    }
}

/// Errors for the optional QUIC 0-RTT entry point.
public enum QUICEarlyDataError: Error, Sendable, Equatable {
    case earlyDataNotSupported
    case resumptionNotSupported
}

// MARK: - TLS 1.3 provider protocol

/// QUIC's TLS 1.3 provider protocol (RFC 9001).
public protocol TLS13Provider: Sendable {
    func startHandshake(isClient: Bool) async throws -> [TLSOutput]

    /// `data` must contain one complete TLS handshake message. The QUIC layer
    /// performs CRYPTO stream reassembly before calling this method.
    func processHandshakeData(_ data: Data, at level: EncryptionLevel) async throws -> [TLSOutput]

    func getLocalTransportParameters() -> Data
    func setLocalTransportParameters(_ params: Data) throws
    func getPeerTransportParameters() -> Data?

    var isHandshakeComplete: Bool { get }
    var isClient: Bool { get }
    var negotiatedALPN: String? { get }

    /// QUIC key phase updates are owned by packet protection, not TLS.
    func requestKeyUpdate() async throws -> [TLSOutput]

    /// QUIC does not expose the generic TLS exporter through this adapter yet.
    func exportKeyingMaterial(label: String, context: Data?, length: Int) throws -> Data

    /// Resumption must be provided when constructing the canonical session.
    func configureResumption(ticket: SessionTicketData, attemptEarlyData: Bool) throws

    var is0RTTAccepted: Bool { get }
    var is0RTTAttempted: Bool { get }
}

// MARK: - Certificate policy callback

/// Application policy hook invoked by a TLS implementation after cryptographic
/// certificate proof succeeds.
public typealias CertificateValidator = @Sendable ([Data]) throws -> (any Sendable)?

// MARK: - Adapter configuration

/// Configuration data shared by QUIC integrations that construct a TLS provider.
///
/// Credential parsing and ownership belong to the provider factory. This value
/// carries bytes and policy only; it does not contain a TLS state machine.
public struct TLSConfiguration: Sendable {
    public var alpnProtocols: [String]
    public var certificatePath: String?
    public var privateKeyPath: String?
    public var certificateChain: [Data]?
    public var privateKey: Data?
    public var privateKeyAlgorithm: SwiftSSLQUICTLSKeyAlgorithm?
    public var verifyPeer: Bool
    public var trustedCACertificates: [Data]?
    public var expectedPeerPublicKey: Data?
    public var allowSelfSigned: Bool
    public var serverName: String?
    public var sessionTicket: Data?
    public var maxEarlyDataSize: UInt32
    public var supportedGroups: [NamedGroup]
    public var requireClientCertificate: Bool
    public var certificateValidator: CertificateValidator?

    public init() {
        self.alpnProtocols = ["h3"]
        self.certificatePath = nil
        self.privateKeyPath = nil
        self.certificateChain = nil
        self.privateKey = nil
        self.privateKeyAlgorithm = nil
        self.verifyPeer = true
        self.trustedCACertificates = nil
        self.expectedPeerPublicKey = nil
        self.allowSelfSigned = false
        self.serverName = nil
        self.sessionTicket = nil
        self.maxEarlyDataSize = 0
        self.supportedGroups = [.x25519, .secp256r1]
        self.requireClientCertificate = false
        self.certificateValidator = nil
    }

    public static func client(
        serverName: String? = nil,
        alpnProtocols: [String] = ["h3"]
    ) -> TLSConfiguration {
        var configuration = TLSConfiguration()
        configuration.serverName = serverName
        configuration.alpnProtocols = alpnProtocols
        return configuration
    }

    public static func server(
        privateKey: Data,
        keyAlgorithm: SwiftSSLQUICTLSKeyAlgorithm,
        certificateChain: [Data],
        alpnProtocols: [String] = ["h3"]
    ) -> TLSConfiguration {
        var configuration = TLSConfiguration()
        configuration.privateKey = privateKey
        configuration.privateKeyAlgorithm = keyAlgorithm
        configuration.certificateChain = certificateChain
        configuration.alpnProtocols = alpnProtocols
        return configuration
    }

    public static func server(
        certificatePath: String,
        privateKeyPath: String,
        alpnProtocols: [String] = ["h3"]
    ) -> TLSConfiguration {
        var configuration = TLSConfiguration()
        configuration.certificatePath = certificatePath
        configuration.privateKeyPath = privateKeyPath
        configuration.alpnProtocols = alpnProtocols
        return configuration
    }

    public static func libp2p(serverName: String? = nil) -> TLSConfiguration {
        var configuration = TLSConfiguration()
        configuration.serverName = serverName
        configuration.alpnProtocols = ["libp2p"]
        return configuration
    }

    public var hasCertificate: Bool {
        certificateChain != nil && privateKey != nil && privateKeyAlgorithm != nil
    }
}
