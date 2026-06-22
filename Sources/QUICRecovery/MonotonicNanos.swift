/// Host-side clock-seam conversion between `ContinuousClock.Instant` / `Duration`
/// and the monotonic `UInt64` nanoseconds that the `QUICRecoveryCore` value types
/// consume.
///
/// The caller-locked adapters (`NewRenoCongestionController`, `CubicCongestionController`,
/// `Pacer`) fix an `epoch` at construction time, convert every incoming `Instant`
/// to epoch-relative nanoseconds before delegating to the core, and convert emitted
/// deadlines back to `Instant`. Conversions are floor-to-nanosecond, which is
/// monotonic, so `<=` ordering of instants is preserved.

import Foundation

/// Epoch-relative monotonic-nanosecond conversion helpers.
enum MonotonicNanos {
    /// Converts a `Duration` to whole nanoseconds, matching the host's
    /// `components`-based decomposition. Negative durations clamp to 0.
    @inline(__always)
    static func nanos(of duration: Duration) -> UInt64 {
        let (seconds, attoseconds) = duration.components
        let ns = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return ns < 0 ? 0 : UInt64(ns)
    }

    /// Converts an `Instant` to epoch-relative nanoseconds.
    @inline(__always)
    static func nanos(from epoch: ContinuousClock.Instant, to instant: ContinuousClock.Instant) -> UInt64 {
        nanos(of: epoch.duration(to: instant))
    }

    /// Reconstructs an `Instant` from epoch-relative nanoseconds.
    @inline(__always)
    static func instant(from epoch: ContinuousClock.Instant, nanos: UInt64) -> ContinuousClock.Instant {
        epoch + .nanoseconds(Int64(clamping: nanos))
    }
}
