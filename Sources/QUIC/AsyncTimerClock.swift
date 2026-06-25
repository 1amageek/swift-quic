// AsyncTimerClock.swift
// The host `AsyncTimer` the QUIC facade injects as the engine's `T` clock seam
// and uses to drive the seam-based timer loop. HOST-ONLY: `ContinuousClock` and
// `Task.sleep` are `@available(*, unavailable)` under Embedded Swift, so the
// whole file is gated `#if !hasFeature(Embedded)`. Under Embedded the embedder
// injects its own `AsyncTimer` (e.g. a POSIX `clock_gettime`-backed one, or its
// executor's timer) — this driver is generic over `Timer: AsyncTimer`, so it
// takes whatever the platform supplies.
//
// This mirrors `swift-p2p-transport`'s `HostAsyncTimer` but lives in the QUIC
// module so the host facade does not take a transport-implementation dependency
// just to obtain a clock.

#if !hasFeature(Embedded)

import _Concurrency
import P2PCoreCrypto

/// A host `AsyncTimer` backed by the standard-library `ContinuousClock`.
///
/// `monotonicNanos()` reports nanoseconds since construction; `sleep(untilNanos:)`
/// suspends via `Task.sleep(until:clock:)`, which is fully cancellation-aware.
/// This is the single timeline the seam-driven `QUICEngineConnection` uses — there
/// is no `Date`/`ContinuousClock` in the driver itself; it all comes through here.
public struct AsyncTimerClock: AsyncTimer {
    private let origin: ContinuousClock.Instant
    private let clock = ContinuousClock()

    public init() {
        self.origin = ContinuousClock.now
    }

    // MARK: - MonotonicClock (time source)

    /// Monotonic nanoseconds since this clock was created.
    public func monotonicNanos() -> UInt64 {
        let elapsed = ContinuousClock.now - origin
        let (seconds, attoseconds) = elapsed.components
        return UInt64(max(0, seconds)) &* 1_000_000_000
            &+ UInt64(max(0, attoseconds) / 1_000_000_000)
    }

    /// Monotonic milliseconds since this clock was created.
    public func monotonicMillis() -> UInt64 {
        monotonicNanos() / 1_000_000
    }

    // MARK: - AsyncTimer (deadline sleep)

    /// Suspends until `monotonicNanos()` reaches `deadlineNanos` (absolute, on the
    /// same monotonic timeline). Returns promptly if already past.
    ///
    /// - Throws: `CancellationError` if the task is cancelled while suspended.
    public func sleep(untilNanos deadlineNanos: UInt64) async throws(CancellationError) {
        let now = monotonicNanos()
        if deadlineNanos <= now { return }
        let waitNanos = deadlineNanos - now
        let instant = ContinuousClock.now.advanced(by: .nanoseconds(waitNanos))
        do {
            try await Task.sleep(until: instant, clock: clock)
        } catch {
            // `Task.sleep` throws only `CancellationError`; re-surface it as the
            // protocol's typed error. No other error type can reach here.
            throw CancellationError()
        }
    }
}

#endif
