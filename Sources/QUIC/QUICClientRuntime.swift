import NetworkingDatagram
import NetworkingTime

/// Concrete runtime environment for a client QUIC session.
public enum QUICClientRuntime<
    TransportType: DatagramTransport,
    TimerType: AsyncTimer,
    CapabilityProvider: QUICTLSCapabilityProviding
>: QUICClientRuntimeEnvironment {
    public typealias Transport = TransportType
    public typealias Timer = TimerType
    public typealias Capabilities = CapabilityProvider
}
