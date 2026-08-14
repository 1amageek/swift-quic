import NetworkingDatagram
import NetworkingTime

/// Concrete runtime environment for a server QUIC session.
public enum QUICServerRuntime<
    TransportType: DatagramTransport,
    TimerType: AsyncTimer,
    CapabilityProvider: QUICTLSCapabilityProviding
>: QUICServerRuntimeEnvironment {
    public typealias Transport = TransportType
    public typealias Timer = TimerType
    public typealias Capabilities = CapabilityProvider
}
