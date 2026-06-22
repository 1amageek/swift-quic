/// Embedded-clean token-bucket pacer (RFC 9002 §7.7) as a value type.
///
/// This is the byte-identical math of the host `Pacer`, expressed as a `struct` with
/// `mutating` methods. Time is injected as a monotonic `UInt64` nanosecond value;
/// the pacer never reads a clock. The host adapter holds a `Mutex<PacerCore>`, reads
/// its `ContinuousClock`, converts to nanoseconds, and calls these methods under the
/// lock — observable behavior (including the 1.3.0 overflow fix) is unchanged.
///
/// Delays are returned as nanosecond counts; the adapter converts back to `Duration`.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.
public struct PacerCore: Sendable {

    /// Current pacing rate in bytes per second.
    public private(set) var rate: UInt64

    /// Available token bucket capacity in bytes.
    private var tokens: UInt64

    /// Maximum burst size in bytes.
    private var maxBurst: UInt64

    /// Last replenish time as injected monotonic nanos.
    private var lastUpdateNanos: UInt64

    /// Whether pacing is enabled.
    public private(set) var isEnabled: Bool

    // MARK: - Initialization

    /// Creates a pacer core.
    ///
    /// - Parameters:
    ///   - rate: Initial pacing rate in bytes per second (0 disables pacing).
    ///   - maxBurst: Maximum burst size in bytes (initial token fill).
    ///   - nowNanos: Current monotonic time in nanoseconds.
    public init(rate: UInt64, maxBurst: UInt64, nowNanos: UInt64) {
        self.rate = rate
        self.tokens = maxBurst
        self.maxBurst = maxBurst
        self.lastUpdateNanos = nowNanos
        self.isEnabled = rate > 0
    }

    // MARK: - Rate Control

    /// Updates the pacing rate.
    public mutating func updateRate(bytesPerSecond: UInt64) {
        rate = bytesPerSecond
        isEnabled = bytesPerSecond > 0
    }

    /// Updates the maximum burst size, clamping current tokens to the new cap.
    public mutating func updateMaxBurst(bytes: UInt64) {
        maxBurst = bytes
        if tokens > bytes {
            tokens = bytes
        }
    }

    /// Current token count (test/diagnostics).
    public var currentTokens: UInt64 {
        tokens
    }

    /// Forces `lastUpdate` into the past to exercise the large-elapsed replenish
    /// path deterministically (regression coverage for the overflow trap).
    public mutating func setLastUpdate(nanos: UInt64) {
        lastUpdateNanos = nanos
    }

    // MARK: - Packet Scheduling

    /// The outcome of attempting to schedule a packet against the token bucket.
    public enum ScheduleResult: Sendable, Equatable {
        /// Pacing is disabled (or rate is 0): the packet may be sent immediately.
        case disabled
        /// Enough tokens were available; they were consumed. Send immediately.
        case immediate
        /// Insufficient tokens; the caller must wait for `tokensNeeded` more bytes
        /// to accumulate at the current `rate`. The adapter computes the `Duration`.
        case insufficient(tokensNeeded: UInt64)
    }

    /// Replenishes tokens, then attempts to consume `bytes`. The delay-to-`Duration`
    /// conversion is left to the adapter so the public API stays byte-identical to
    /// the host (which builds `Duration.seconds(...)` with sub-nanosecond precision).
    public mutating func schedule(bytes: UInt64, nowNanos: UInt64) -> ScheduleResult {
        // A zero (or unset) rate means "no pacing" — never divide by zero in the adapter.
        guard isEnabled, rate > 0 else { return .disabled }

        replenishTokens(nowNanos: nowNanos)

        if tokens >= bytes {
            tokens -= bytes
            return .immediate
        }

        return .insufficient(tokensNeeded: bytes - tokens)
    }

    /// Consumes tokens for a packet being sent.
    public mutating func consume(bytes: UInt64, nowNanos: UInt64) {
        guard isEnabled else { return }

        replenishTokens(nowNanos: nowNanos)

        if tokens >= bytes {
            tokens -= bytes
        } else {
            tokens = 0
        }
    }

    /// Replenishes tokens by elapsed time, clamped to headroom (overflow-safe).
    ///
    /// Computing against the headroom (and clamping the `Double` product before
    /// converting) avoids the `Double`→`UInt64` conversion overflow and the
    /// `UInt64` addition overflow that a naive `UInt64(elapsedSeconds * rate)` hits.
    public mutating func replenishTokens(nowNanos: UInt64) {
        // Guard against a non-monotonic / zero step: never reduce, never produce.
        guard nowNanos > lastUpdateNanos else { lastUpdateNanos = nowNanos; return }
        let elapsedNanos = nowNanos - lastUpdateNanos

        let headroom = maxBurst > tokens ? maxBurst - tokens : 0
        if headroom == 0 {
            lastUpdateNanos = nowNanos
            return
        }

        let elapsedSeconds = Double(elapsedNanos) / 1e9
        let produced = elapsedSeconds * Double(rate)
        // Clamp to headroom before the UInt64 conversion so neither the conversion
        // nor the addition can overflow. `produced` is bounded and finite here.
        let newTokens: UInt64
        if produced.isFinite, produced > 0 {
            newTokens = produced >= Double(headroom) ? headroom : UInt64(produced)
        } else {
            newTokens = 0
        }

        tokens += newTokens          // newTokens <= headroom, so this cannot overflow maxBurst
        lastUpdateNanos = nowNanos
    }

    /// Available tokens after replenishing to `nowNanos`.
    public mutating func availableTokens(nowNanos: UInt64) -> UInt64 {
        replenishTokens(nowNanos: nowNanos)
        return tokens
    }
}
