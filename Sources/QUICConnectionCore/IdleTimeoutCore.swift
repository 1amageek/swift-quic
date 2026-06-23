/// Embedded-clean idle-timeout core (RFC 9000 §10.1) as a value type.
///
/// This is the byte-identical idle-timeout logic of the host `IdleTimeoutManager`,
/// expressed as a `struct` operating purely on monotonic `UInt64` nanosecond values.
/// The host `IdleTimeoutManager` keeps `Duration`-typed public fields plus a
/// `Mutex` and a `ContinuousClock` epoch; it converts `Duration`/`Instant` to/from
/// nanoseconds and delegates the math here, so observable behavior is unchanged.
///
/// RFC 9000 §10.1: the effective idle timeout is the minimum of the local and peer
/// `max_idle_timeout` values; a value of 0 means "no timeout" on that side. Keep-alive
/// is sent at half the effective timeout.
///
/// Embedded-clean: no Foundation, no `Duration`, no `ContinuousClock`, no `any`,
/// no `Mutex`.
public struct IdleTimeoutCore: Sendable, Equatable {

    // MARK: - State (all nanoseconds; 0 == no timeout)

    /// Last activity time in epoch-relative nanoseconds (packet sent or received).
    public private(set) var lastActivityNanos: UInt64

    /// Effective idle timeout in nanoseconds (min of local and peer; 0 == no timeout).
    public private(set) var effectiveTimeoutNanos: UInt64

    /// Local max idle timeout from configuration, in nanoseconds (0 == no timeout).
    public private(set) var localTimeoutNanos: UInt64

    /// Peer's max idle timeout from transport parameters, in nanoseconds.
    /// `nil` until received; 0 from the peer means "no timeout" (cleared to `nil`).
    public private(set) var peerTimeoutNanos: UInt64?

    /// Current lifecycle state.
    public private(set) var currentState: State

    /// Whether keep-alive PINGs are enabled.
    public private(set) var keepAliveEnabled: Bool

    /// Keep-alive interval in nanoseconds, or `nil` if keep-alive is disabled.
    public private(set) var keepAliveIntervalNanos: UInt64?

    // MARK: - State

    /// Lifecycle state of the idle-timeout core.
    public enum State: Sendable, Equatable {
        /// Connection is active.
        case active
        /// Connection timed out.
        case timedOut
        /// Connection was closed gracefully.
        case closed
    }

    // MARK: - Initialization

    /// Creates an idle-timeout core.
    ///
    /// - Parameters:
    ///   - localTimeoutNanos: Local max idle timeout in nanoseconds (0 == no timeout).
    ///   - nowNanos: Current epoch-relative time in nanoseconds (initial last-activity).
    public init(localTimeoutNanos: UInt64, nowNanos: UInt64) {
        self.localTimeoutNanos = localTimeoutNanos
        self.effectiveTimeoutNanos = localTimeoutNanos
        self.peerTimeoutNanos = nil
        self.lastActivityNanos = nowNanos
        self.currentState = .active
        self.keepAliveEnabled = false
        self.keepAliveIntervalNanos = nil
    }

    // MARK: - Configuration

    /// Sets the peer's max idle timeout (RFC 9000 §10.1) and recomputes the
    /// effective timeout as the minimum of the two non-zero values.
    ///
    /// - Parameter peerTimeoutNanos: Peer's `max_idle_timeout` in nanoseconds
    ///   (0 means the peer advertises no timeout; use the local value alone).
    public mutating func setPeerTimeout(_ peerTimeoutNanos: UInt64) {
        if peerTimeoutNanos == 0 {
            // Peer advertises no timeout - use local only.
            self.peerTimeoutNanos = nil
            effectiveTimeoutNanos = localTimeoutNanos
        } else {
            self.peerTimeoutNanos = peerTimeoutNanos
            // Effective timeout is the minimum of local and peer. If local is 0
            // (no timeout from our side), use the peer value.
            if localTimeoutNanos == 0 {
                effectiveTimeoutNanos = peerTimeoutNanos
            } else {
                effectiveTimeoutNanos = localTimeoutNanos < peerTimeoutNanos
                    ? localTimeoutNanos
                    : peerTimeoutNanos
            }
        }

        // Update keep-alive interval if enabled.
        if keepAliveEnabled {
            keepAliveIntervalNanos = effectiveTimeoutNanos / 2
        }
    }

    /// Enables or disables keep-alive PINGs (interval = effective timeout / 2).
    public mutating func setKeepAlive(enabled: Bool) {
        keepAliveEnabled = enabled
        keepAliveIntervalNanos = enabled ? effectiveTimeoutNanos / 2 : nil
    }

    // MARK: - Activity Tracking

    /// Records activity (packet sent or received). No-op unless `active`.
    public mutating func recordActivity(nowNanos: UInt64) {
        guard currentState == .active else { return }
        lastActivityNanos = nowNanos
    }

    /// Marks the connection as closed gracefully.
    public mutating func markClosed() {
        currentState = .closed
    }

    // MARK: - Timeout Checking

    /// Checks whether the connection has timed out, transitioning to `.timedOut`
    /// the first time the deadline has passed.
    ///
    /// - Returns: `true` if timed out (now or already).
    public mutating func checkTimeout(nowNanos: UInt64) -> Bool {
        guard currentState == .active else {
            return currentState == .timedOut
        }
        // No timeout if effective timeout is 0.
        guard effectiveTimeoutNanos > 0 else {
            return false
        }
        let deadline = lastActivityNanos &+ effectiveTimeoutNanos
        if nowNanos >= deadline {
            currentState = .timedOut
            return true
        }
        return false
    }

    /// Time until idle timeout in nanoseconds, or `nil` if already timed out /
    /// closed / no timeout configured. Returns 0 if the deadline has passed.
    public func timeUntilTimeoutNanos(nowNanos: UInt64) -> UInt64? {
        guard currentState == .active else { return nil }
        guard effectiveTimeoutNanos > 0 else { return nil }
        let deadline = lastActivityNanos &+ effectiveTimeoutNanos
        if deadline <= nowNanos {
            return 0
        }
        return deadline - nowNanos
    }

    /// Time until the next keep-alive should be sent in nanoseconds, or `nil` if
    /// keep-alive is disabled / not active. Returns 0 if the deadline has passed.
    public func timeUntilKeepAliveNanos(nowNanos: UInt64) -> UInt64? {
        guard currentState == .active else { return nil }
        guard let interval = keepAliveIntervalNanos else { return nil }
        let deadline = lastActivityNanos &+ interval
        if deadline <= nowNanos {
            return 0
        }
        return deadline - nowNanos
    }

    /// Whether a keep-alive PING is due now.
    public func shouldSendKeepAlive(nowNanos: UInt64) -> Bool {
        guard currentState == .active else { return false }
        guard let interval = keepAliveIntervalNanos else { return false }
        let deadline = lastActivityNanos &+ interval
        return nowNanos >= deadline
    }

    // MARK: - Deadline Computation

    /// The next deadline (earliest of timeout / keep-alive) as epoch-relative
    /// nanoseconds, or `nil` if there is no deadline (not active, or no timer set).
    public func nextDeadlineNanos() -> UInt64? {
        guard currentState == .active else { return nil }

        var earliest: UInt64? = nil

        if effectiveTimeoutNanos > 0 {
            earliest = lastActivityNanos &+ effectiveTimeoutNanos
        }
        if let interval = keepAliveIntervalNanos {
            let keepAliveDeadline = lastActivityNanos &+ interval
            if let current = earliest {
                earliest = keepAliveDeadline < current ? keepAliveDeadline : current
            } else {
                earliest = keepAliveDeadline
            }
        }

        return earliest
    }
}
