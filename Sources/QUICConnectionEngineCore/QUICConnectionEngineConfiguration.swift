import QUICWire
import QUICConnectionCore

public enum QUICEngineRole: Sendable, Equatable {
    case client
    case server
}

/// Protocol and transport tuning consumed by the sans-I/O QUIC engine.
///
/// TLS peer authentication belongs to `swift-tls`. Entropy belongs to the
/// component that creates connection IDs or path challenges. The packet engine
/// therefore retains neither capability as an unused closure.
public struct QUICConnectionEngineConfiguration: Sendable {
    public var role: QUICEngineRole
    public var version: QUICVersion
    public var localConnectionID: ConnectionID
    public var initialPeerConnectionID: ConnectionID
    public var originalDestinationConnectionID: ConnectionID
    public var localTransportParameters: TransportParametersCore
    public var maxDatagramSize: Int
    public var idleTimeoutNanos: UInt64
    public var maxAckDelayNanos: UInt64
    public var pathValidationTimeoutNanos: UInt64
    var aeadUsageLimits: QUICAEADUsageLimits

    public init(
        role: QUICEngineRole,
        version: QUICVersion = .v1,
        localConnectionID: ConnectionID,
        initialPeerConnectionID: ConnectionID,
        originalDestinationConnectionID: ConnectionID,
        localTransportParameters: TransportParametersCore,
        maxDatagramSize: Int = 1200,
        idleTimeoutNanos: UInt64 = 30_000_000_000,
        maxAckDelayNanos: UInt64 = 25_000_000,
        pathValidationTimeoutNanos: UInt64 = 3_000_000_000
    ) {
        self.role = role
        self.version = version
        self.localConnectionID = localConnectionID
        self.initialPeerConnectionID = initialPeerConnectionID
        self.originalDestinationConnectionID = originalDestinationConnectionID
        self.localTransportParameters = localTransportParameters
        self.maxDatagramSize = maxDatagramSize
        self.idleTimeoutNanos = idleTimeoutNanos
        self.maxAckDelayNanos = maxAckDelayNanos
        self.pathValidationTimeoutNanos = pathValidationTimeoutNanos
        self.aeadUsageLimits = QUICAEADUsageLimits()
    }
}
