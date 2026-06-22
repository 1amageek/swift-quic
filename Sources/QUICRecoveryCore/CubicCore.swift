/// Embedded-clean CUBIC congestion controller (RFC 9438) as a value type.
///
/// This is the byte-identical math of the host `CubicCongestionController`,
/// expressed as a `struct` with `mutating` methods. Time is injected as a monotonic
/// `UInt64` nanosecond value; the controller never reads a clock. Elapsed seconds
/// for the cubic curve are derived as `Double(nowNanos - epochNanos) / 1e9`, which
/// equals the host's `Duration.components` decomposition because the adapter
/// converts each `ContinuousClock.Instant` to epoch-relative nanoseconds identically.
///
/// The host adapter holds a `Mutex<CubicCore>`, reads its `ContinuousClock`, converts
/// to nanoseconds, and calls these methods under the lock — observable behavior is
/// unchanged.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`. The
/// cube root needed for `K` (RFC 9438 §4.2) routes through the libm `cbrt` symbol on
/// the host (byte-identical to the original implementation) and an Embedded-safe
/// Newton/Halley fallback under Embedded Swift (where libm `cbrt` is not in scope).
#if !hasFeature(Embedded)
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif
#endif

public struct CubicCore: Sendable {

    // MARK: - CUBIC Constants (RFC 9438 §4 and §5)

    /// CUBIC scaling constant `C` (RFC 9438 §5).
    private static let cubicC: Double = 0.4

    /// CUBIC multiplicative decrease factor `beta_cubic` (RFC 9438 §4.6).
    private static let cubicBeta: Double = 0.7

    // MARK: - State (RFC 9002 §7.1 / RFC 9438 §4)

    /// Current congestion window in bytes (fractional, clamped at read time).
    private var congestionWindow: Double

    /// Slow-start threshold in bytes (`Double.greatestFiniteMagnitude` ~ infinity).
    private var ssthresh: Double

    /// Recovery start time (injected monotonic nanos), or nil when not in recovery.
    public private(set) var recoveryStartNanos: UInt64?

    /// `W_max`: window just before the last congestion event.
    private var wMax: Double

    /// `W_last_max`: `W_max` from the previous congestion event (fast convergence).
    private var wLastMax: Double

    /// `K`: time period to reach `W_max` again, in seconds (RFC 9438 §4.2).
    private var k: Double

    /// Cubic epoch start (injected monotonic nanos), or nil before the first event.
    private var epochStartNanos: UInt64?

    /// `W_est`: the Reno-friendly window estimate (RFC 9438 §4.3).
    private var wEstReno: Double

    /// Accumulated acked bytes used by the Reno-friendly estimator.
    private var bytesAcked: Double

    // MARK: - Pacing state

    /// Next send time as injected monotonic nanos.
    public private(set) var nextSendNanos: UInt64

    /// Pacing rate in bytes per nanosecond.
    private var pacingRate: Double

    /// Remaining burst tokens.
    private var burstTokens: Int

    // MARK: - Configuration

    private var maxDatagramSize: Int
    private var minimumWindow: Int

    // MARK: - Initialization

    /// Creates a CUBIC controller core (RFC 9002 §7.2 initial window).
    public init(maxDatagramSize: Int = CongestionCoreConstants.maxDatagramSize) {
        let minimumWindow = CongestionCoreConstants.minimumWindow(maxDatagramSize: maxDatagramSize)
        let initialWindow = CongestionCoreConstants.initialWindow(maxDatagramSize: maxDatagramSize)
        self.congestionWindow = Double(initialWindow)
        self.ssthresh = Double.greatestFiniteMagnitude
        self.recoveryStartNanos = nil
        self.wMax = 0
        self.wLastMax = 0
        self.k = 0
        self.epochStartNanos = nil
        self.wEstReno = 0
        self.bytesAcked = 0
        self.nextSendNanos = 0
        self.pacingRate = 0
        self.burstTokens = CongestionCoreConstants.initialBurstTokens
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = minimumWindow
    }

    // MARK: - State Queries

    /// The clamped integer congestion window (never below the minimum).
    public var clampedWindow: Int {
        max(minimumWindow, Int(congestionWindow.rounded()))
    }

    /// The current congestion-control phase.
    ///
    /// Mirrors the host: compares the raw (fractional) window to `ssthresh`.
    public var state: CongestionCoreState {
        if let start = recoveryStartNanos {
            return .recovery(startNanos: start)
        } else if congestionWindow < ssthresh {
            return .slowStart
        } else {
            return .congestionAvoidance
        }
    }

    /// Available window for sending given bytes currently in flight.
    public func availableWindow(bytesInFlight: Int) -> Int {
        max(0, clampedWindow - bytesInFlight)
    }

    /// The next pacing send time in nanos, or nil if a packet can be sent now.
    public var nextSendNanosOrImmediate: UInt64? {
        if burstTokens > 0 { return nil }
        if pacingRate <= 0 { return nil }
        return nextSendNanos
    }

    // MARK: - Event Handlers

    /// Records a packet send and advances the pacing clock (RFC 9002 §7.7).
    public mutating func onPacketSent(bytes: Int, nowNanos: UInt64) {
        if burstTokens > 0 {
            burstTokens -= 1
        } else if pacingRate > 0 {
            let intervalNanos = Double(bytes) / pacingRate
            let nanos = Int64(intervalNanos)
            nextSendNanos = nowNanos &+ UInt64(bitPattern: nanos)
        }
    }

    /// Processes acknowledged packets, growing the window per phase.
    public mutating func onPacketsAcknowledged(
        packets: [CongestionPacket],
        nowNanos: UInt64,
        rtt: RTTSnapshot
    ) {
        for packet in packets {
            guard packet.inFlight else { continue }

            if let recoveryStart = recoveryStartNanos {
                if packet.timeSentNanos <= recoveryStart {
                    continue
                }
                recoveryStartNanos = nil
            }

            let acked = Double(packet.sentBytes)

            if congestionWindow < ssthresh {
                // Slow start: exponential growth, identical to NewReno.
                congestionWindow += acked
            } else {
                cubicCongestionAvoidance(ackedBytes: acked, nowNanos: nowNanos, rtt: rtt)
            }
        }

        updatePacingRate(rtt: rtt)
    }

    /// Processes detected losses (RFC 9002 §7.3.2: one reduction per RTT).
    public mutating func onPacketsLost(
        packets: [CongestionPacket],
        nowNanos: UInt64,
        rtt: RTTSnapshot
    ) {
        guard !packets.isEmpty else { return }
        if recoveryStartNanos != nil { return }
        enterRecovery(nowNanos: nowNanos)
        updatePacingRate(rtt: rtt)
    }

    /// Treats an ECN-CE mark the same as packet loss.
    public mutating func onECNCongestionEvent(nowNanos: UInt64) {
        if recoveryStartNanos != nil { return }
        enterRecovery(nowNanos: nowNanos)
    }

    /// Collapses the window and re-enters slow start (RFC 9002 §7.6.2).
    public mutating func onPersistentCongestion() {
        congestionWindow = Double(minimumWindow)
        ssthresh = Double.greatestFiniteMagnitude
        wMax = 0
        wLastMax = 0
        k = 0
        epochStartNanos = nil
        wEstReno = 0
        bytesAcked = 0
        recoveryStartNanos = nil
        burstTokens = CongestionCoreConstants.initialBurstTokens
        pacingRate = 0
    }

    /// Raises the tracked datagram size / minimum-window floor (RFC 9000 §14).
    public mutating func updateMaxDatagramSize(_ maxDatagramSize: Int) {
        guard maxDatagramSize > self.maxDatagramSize else { return }
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = 2 * maxDatagramSize
    }

    // MARK: - Debug

    /// A compact diagnostic string mirroring the host description.
    public var description: String {
        let stateStr: String
        if recoveryStartNanos != nil {
            stateStr = "recovery"
        } else if congestionWindow < ssthresh {
            stateStr = "slow_start"
        } else {
            stateStr = "congestion_avoidance"
        }
        let cwnd = clampedWindow
        let ssthreshStr = ssthresh == Double.greatestFiniteMagnitude
            ? "inf"
            : String(Int(ssthresh.rounded()))
        return "CUBIC(cwnd=\(cwnd), ssthresh=\(ssthreshStr), wMax=\(Int(wMax.rounded())), state=\(stateStr))"
    }

    // MARK: - Private helpers

    /// Cube root of a non-negative value.
    ///
    /// On the host this is the libm `cbrt` symbol, byte-identical to the original
    /// `CubicCongestionController`. Under Embedded Swift (where libm `cbrt` is not in
    /// scope) it uses a Halley-iteration fallback seeded from the binary exponent;
    /// `K` only feeds the cubic-curve growth region (never the exact-value paths), so
    /// the tiny ULP difference does not change observable congestion-control behavior.
    @inline(__always)
    static func cubeRoot(_ x: Double) -> Double {
        #if !hasFeature(Embedded)
        return cbrt(x)
        #else
        if x == 0 || !x.isFinite { return x }
        let negative = x < 0
        let a = negative ? -x : x
        // Seed: y0 = 2^(exponent/3) keeps the iteration in the right magnitude.
        var y = Double(sign: .plus, exponent: a.exponent / 3, significand: 1.0)
        if y == 0 { y = a }
        // Halley's method for f(y) = y^3 - a converges cubically.
        for _ in 0..<8 {
            let y3 = y * y * y
            let denom = y3 + y3 + a
            if denom == 0 { break }
            y = y * (y3 + a + a) / denom
        }
        return negative ? -y : y
        #endif
    }

    /// Converts a non-negative nanosecond count to seconds, reproducing the host's
    /// `Duration.components`-based decomposition byte-for-byte:
    /// `Double(seconds) + Double(attoseconds) / 1e18`, where for an N-nanosecond
    /// duration `seconds = N / 1e9` and `attoseconds = (N % 1e9) * 1e9`.
    @inline(__always)
    private static func nanosToSeconds(_ nanos: UInt64) -> Double {
        let seconds = nanos / 1_000_000_000
        let subNanos = nanos % 1_000_000_000
        let attoseconds = subNanos &* 1_000_000_000
        return Double(seconds) + Double(attoseconds) / 1e18
    }

    /// Enters recovery and applies the CUBIC multiplicative decrease with fast
    /// convergence (RFC 9438 §4.6, §4.7).
    private mutating func enterRecovery(nowNanos: UInt64) {
        recoveryStartNanos = nowNanos

        let cwnd = congestionWindow

        if cwnd < wLastMax {
            wLastMax = cwnd
            wMax = cwnd * (1.0 + Self.cubicBeta) / 2.0
        } else {
            wLastMax = cwnd
            wMax = cwnd
        }

        let reduced = cwnd * Self.cubicBeta
        let minWindow = Double(minimumWindow)
        congestionWindow = max(reduced, minWindow)
        ssthresh = max(reduced, minWindow)

        epochStartNanos = nil
        wEstReno = congestionWindow
        bytesAcked = 0
    }

    /// One congestion-avoidance step using the cubic curve and the Reno-friendly
    /// estimate (RFC 9438 §4.1–§4.4).
    private mutating func cubicCongestionAvoidance(
        ackedBytes: Double,
        nowNanos: UInt64,
        rtt: RTTSnapshot
    ) {
        let mss = Double(maxDatagramSize)

        if epochStartNanos == nil {
            epochStartNanos = nowNanos
            if wMax < congestionWindow {
                k = 0
                wMax = congestionWindow
            } else {
                k = Self.cubeRoot(wMax * (1.0 - Self.cubicBeta) / Self.cubicC)
            }
            wEstReno = congestionWindow
            bytesAcked = 0
        }

        // Elapsed time since the epoch start, in seconds. The decomposition into
        // (seconds, sub-second) mirrors the host's `Duration.components` arithmetic
        // exactly so the cubic curve is byte-identical.
        let epoch = epochStartNanos ?? nowNanos
        let elapsedNanos = nowNanos >= epoch ? nowNanos - epoch : 0
        let t = Self.nanosToSeconds(elapsedNanos)

        // RFC 9438 §4.1: W_cubic(t) = C * (t - K)^3 + W_max.
        let tMinusK = t - k
        let wCubic = Self.cubicC * (tMinusK * tMinusK * tMinusK) + wMax

        // RFC 9438 §4.3: Reno-friendly region (AIMD estimate).
        bytesAcked += ackedBytes
        if bytesAcked >= congestionWindow {
            wEstReno += mss
            bytesAcked -= congestionWindow
        }

        // RFC 9438 §4.2: target increase toward W_cubic over the next RTT.
        let rttSeconds: Double
        if rtt.hasEstimate {
            rttSeconds = Self.nanosToSeconds(rtt.smoothedRTTNanos)
        } else {
            rttSeconds = 0
        }
        let tNext = (t + rttSeconds) - k
        let wCubicNext = Self.cubicC * (tNext * tNext * tNext) + wMax

        let target: Double
        if wCubicNext < congestionWindow {
            target = congestionWindow
        } else if wCubicNext > 1.5 * congestionWindow {
            target = 1.5 * congestionWindow
        } else {
            target = wCubicNext
        }

        let cubicIncrement: Double
        if congestionWindow > 0 {
            cubicIncrement = (target - congestionWindow) / congestionWindow * ackedBytes
        } else {
            cubicIncrement = 0
        }

        if wEstReno > wCubic {
            let renoIncrement = max(0, wEstReno - congestionWindow)
            congestionWindow += renoIncrement
        } else {
            congestionWindow += max(0, cubicIncrement)
        }
    }

    /// Updates the pacing rate based on the current cwnd and RTT (RFC 9002 §7.7).
    private mutating func updatePacingRate(rtt: RTTSnapshot) {
        guard rtt.hasEstimate else { return }
        let smoothedNanos = rtt.smoothedRTTNanos
        if smoothedNanos > 0 {
            pacingRate = Double(clampedWindow) / Double(smoothedNanos)
        }
    }
}
