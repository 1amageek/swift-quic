import NetworkingDatagram
import NetworkingTime
import QUICTLS

/// Compile-time capabilities required by one QUIC connection data path.
///
/// Grouping related associated types behind one environment keeps reference-type
/// metadata portable while preserving static dispatch for transport and timer I/O.
public protocol QUICRuntimeEnvironment: Sendable {
    associatedtype Transport: DatagramTransport
    associatedtype Timer: AsyncTimer
}

public protocol QUICClientRuntimeEnvironment: QUICRuntimeEnvironment {
    associatedtype Capabilities: QUICTLSCapabilityProviding
}

public enum DefaultQUICClientRuntime<
    Base: QUICRuntimeEnvironment
>: QUICClientRuntimeEnvironment {
    public typealias Transport = Base.Transport
    public typealias Timer = Base.Timer
    public typealias Capabilities = NoExternalQUICTLSCapabilities
}

public protocol QUICServerRuntimeEnvironment: QUICRuntimeEnvironment {
    associatedtype Capabilities: QUICTLSCapabilityProviding
}

public enum DefaultQUICServerRuntime<
    Base: QUICRuntimeEnvironment
>: QUICServerRuntimeEnvironment {
    public typealias Transport = Base.Transport
    public typealias Timer = Base.Timer
    public typealias Capabilities = NoExternalQUICTLSCapabilities
}
