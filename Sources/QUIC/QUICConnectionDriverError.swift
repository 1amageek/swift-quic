import NetworkingDatagram
import NetworkingTime
import QUICTLS
import QUICConnectionCore
import QUICConnectionEngineCore

/// Failures produced while driving the sans-I/O engine over platform I/O.
public enum QUICConnectionDriverError: Error, Sendable {
    case cancelled
    case transport(DatagramError)
    case time(TimeError)
    case engine(QUICEngineError)
    case tls(QUICTLSHandshakeError)
    case transportParameters(TransportParameterCodecError)
    case tlsCapability(QUICTLSCapabilityError)
}

/// Operational failures from an external TLS capability provider.
public enum QUICTLSCapabilityError: Error, Sendable, Equatable {
    case unavailable
    case invalidResponse
    case providerFailure(String)
}
