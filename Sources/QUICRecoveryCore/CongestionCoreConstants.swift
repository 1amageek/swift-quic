/// Embedded-clean congestion-control constants (RFC 9002 §7 / RFC 9438).
///
/// Numeric constants shared by the value-type congestion controllers. Clock and
/// scheduling concerns remain outside this target.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

/// Numeric congestion-control constants used by the value-type controllers.
public enum CongestionCoreConstants {
    /// Default maximum datagram size in bytes (RFC 9002 §7.2).
    public static let maxDatagramSize: Int = 1200

    /// Loss reduction factor for NewReno (RFC 9002 §7.3.2): 0.5.
    public static let lossReductionFactor: Double = 0.5

    /// Initial burst tokens for pacing: number of packets sendable immediately at
    /// connection start.
    public static let initialBurstTokens: Int = 10

    /// Computes the RFC 9002 §7.2 initial congestion window for a datagram size.
    @inline(__always)
    public static func initialWindow(maxDatagramSize: Int) -> Int {
        min(10 * maxDatagramSize, max(14720, 2 * maxDatagramSize))
    }

    /// Computes the RFC 9002 §7.2 minimum congestion window for a datagram size.
    @inline(__always)
    public static func minimumWindow(maxDatagramSize: Int) -> Int {
        2 * maxDatagramSize
    }
}
