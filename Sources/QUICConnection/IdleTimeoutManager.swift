/// Idle Timeout Manager (RFC 9000 Section 10.1)
///
/// Manages idle timeout for QUIC connections:
/// - Calculates effective timeout as min(local, peer) values
/// - Tracks last activity time
/// - Provides keep-alive scheduling
/// - Signals when timeout has occurred
///
/// This is the host adapter over the Embedded-clean value type
/// `QUICConnectionCore.IdleTimeoutCore`. It keeps the `Mutex`, fixes a
/// `ContinuousClock` epoch, converts `Duration`/`Instant` to/from monotonic
/// nanoseconds, and drives the core under the lock. Observable behavior is
/// identical to the prior `Duration`/`ContinuousClock` implementation.

import Foundation
import Synchronization
import QUICCore
import QUICConnectionCore

// MARK: - Idle Timeout State

/// State of the idle timeout manager
public enum IdleTimeoutState: Sendable {
    /// Connection is active
    case active
    /// Connection timed out
    case timedOut
    /// Connection was closed gracefully
    case closed
}

extension IdleTimeoutState {
    /// Maps the Embedded core's lifecycle state to the public adapter state.
    init(_ coreState: IdleTimeoutCore.State) {
        switch coreState {
        case .active:
            self = .active
        case .timedOut:
            self = .timedOut
        case .closed:
            self = .closed
        }
    }
}

// MARK: - Idle Timeout Manager

/// Manages idle timeout for a single connection
public final class IdleTimeoutManager: Sendable {

    private let state: Mutex<IdleTimeoutCore>

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    // MARK: - Initialization

    /// Creates an idle timeout manager
    /// - Parameter localTimeout: Local max idle timeout from configuration
    public init(localTimeout: Duration = .seconds(30)) {
        let epoch = ContinuousClock.now
        self.epoch = epoch
        let localNanos = Self.nanos(of: localTimeout)
        self.state = Mutex(IdleTimeoutCore(localTimeoutNanos: localNanos, nowNanos: 0))
    }

    // MARK: - Configuration

    /// Sets the peer's max idle timeout from transport parameters
    /// - Parameter timeoutMs: Peer's max_idle_timeout in milliseconds (0 means no timeout)
    public func setPeerTimeout(_ timeoutMs: UInt64) {
        // The host stored the peer timeout as `Duration.milliseconds(Int64(timeoutMs))`;
        // mirror that conversion exactly so the effective-timeout math is unchanged.
        let peerNanos = timeoutMs == 0 ? 0 : Self.nanos(of: .milliseconds(Int64(timeoutMs)))
        state.withLock { $0.setPeerTimeout(peerNanos) }
    }

    /// Enables keep-alive PINGs
    /// - Parameter enabled: Whether to enable keep-alive
    public func setKeepAlive(enabled: Bool) {
        state.withLock { $0.setKeepAlive(enabled: enabled) }
    }

    // MARK: - Activity Tracking

    /// Records activity (packet sent or received)
    public func recordActivity() {
        let nowNanos = currentNanos()
        state.withLock { $0.recordActivity(nowNanos: nowNanos) }
    }

    /// Marks the connection as closed
    public func markClosed() {
        state.withLock { $0.markClosed() }
    }

    // MARK: - Timeout Checking

    /// Checks if the connection has timed out
    /// - Returns: true if timed out
    public func checkTimeout() -> Bool {
        let nowNanos = currentNanos()
        return state.withLock { $0.checkTimeout(nowNanos: nowNanos) }
    }

    /// Gets the time until idle timeout
    /// - Returns: Duration until timeout, or nil if already timed out or no timeout configured
    public func timeUntilTimeout() -> Duration? {
        let nowNanos = currentNanos()
        return state.withLock { core in
            guard let nanos = core.timeUntilTimeoutNanos(nowNanos: nowNanos) else { return nil }
            return .nanoseconds(Int64(clamping: nanos))
        }
    }

    /// Gets the time until next keep-alive should be sent
    /// - Returns: Duration until keep-alive needed, or nil if not enabled
    public func timeUntilKeepAlive() -> Duration? {
        let nowNanos = currentNanos()
        return state.withLock { core in
            guard let nanos = core.timeUntilKeepAliveNanos(nowNanos: nowNanos) else { return nil }
            return .nanoseconds(Int64(clamping: nanos))
        }
    }

    /// Checks if a keep-alive PING should be sent
    /// - Returns: true if keep-alive is due
    public func shouldSendKeepAlive() -> Bool {
        let nowNanos = currentNanos()
        return state.withLock { $0.shouldSendKeepAlive(nowNanos: nowNanos) }
    }

    // MARK: - Deadline Computation

    /// Gets the next deadline (timeout or keep-alive)
    /// - Returns: The earliest deadline, or nil if no deadline
    public func nextDeadline() -> ContinuousClock.Instant? {
        return state.withLock { core in
            guard let nanos = core.nextDeadlineNanos() else { return nil }
            return Self.instant(from: epoch, nanos: nanos)
        }
    }

    // MARK: - Properties

    /// Current state
    public var currentState: IdleTimeoutState {
        IdleTimeoutState(state.withLock { $0.currentState })
    }

    /// Effective idle timeout
    public var effectiveTimeout: Duration {
        .nanoseconds(Int64(clamping: state.withLock { $0.effectiveTimeoutNanos }))
    }

    /// Local idle timeout
    public var localTimeout: Duration {
        .nanoseconds(Int64(clamping: state.withLock { $0.localTimeoutNanos }))
    }

    /// Peer's idle timeout (if received)
    public var peerTimeout: Duration? {
        state.withLock { core in
            guard let nanos = core.peerTimeoutNanos else { return nil }
            return .nanoseconds(Int64(clamping: nanos))
        }
    }

    /// Last activity time
    public var lastActivity: ContinuousClock.Instant {
        Self.instant(from: epoch, nanos: state.withLock { $0.lastActivityNanos })
    }

    /// Whether keep-alive is enabled
    public var keepAliveEnabled: Bool {
        state.withLock { $0.keepAliveEnabled }
    }

    // MARK: - Clock seam

    /// Current epoch-relative time in monotonic nanoseconds.
    private func currentNanos() -> UInt64 {
        Self.nanos(of: epoch.duration(to: ContinuousClock.now))
    }

    /// Converts a `Duration` to whole nanoseconds (negative clamps to 0), matching
    /// the host's `components`-based decomposition.
    @inline(__always)
    private static func nanos(of duration: Duration) -> UInt64 {
        let (seconds, attoseconds) = duration.components
        let ns = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return ns < 0 ? 0 : UInt64(ns)
    }

    /// Reconstructs an `Instant` from epoch-relative nanoseconds.
    @inline(__always)
    private static func instant(from epoch: ContinuousClock.Instant, nanos: UInt64) -> ContinuousClock.Instant {
        epoch + .nanoseconds(Int64(clamping: nanos))
    }
}

// MARK: - Idle Timeout Integration

/// Extension to integrate with transport parameters
extension IdleTimeoutManager {
    /// Updates from received transport parameters
    /// - Parameter params: The peer's transport parameters
    public func updateFromTransportParameters(_ params: TransportParameters) {
        setPeerTimeout(params.maxIdleTimeout)
    }

    /// Creates transport parameters value
    /// - Returns: The max_idle_timeout value to send in milliseconds
    public func maxIdleTimeoutValue() -> UInt64 {
        let nanos = state.withLock { $0.localTimeoutNanos }
        // Match the host's `seconds * 1000 + attoseconds / 1e15` millisecond reduction.
        return nanos / 1_000_000
    }
}
