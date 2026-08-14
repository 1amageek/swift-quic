import NetworkingDatagram
import NetworkingTime

/// Concrete transport-and-timer environment for `QUICEngineConnection`.
public enum QUICRuntime<
    TransportType: DatagramTransport,
    TimerType: AsyncTimer
>: QUICRuntimeEnvironment {
    public typealias Transport = TransportType
    public typealias Timer = TimerType
}
