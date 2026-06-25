// FacadeLock.swift
// The facade's value-protecting lock — `Synchronization.Mutex` on host, an
// `Atomic`-spinlock box under Embedded (where `Synchronization.Mutex` is
// unavailable).
//
// The QUIC facade is "the caller that locks": `ManagedConnection` is a
// `final class & Sendable` that holds the value-type, sans-IO
// `QUICConnectionEngine` behind this lock, so its public methods are
// `Sendable`-safe. The engine itself holds no lock; the facade serialises every
// mutation here. This mirrors the proven swift-tls Tier-1 facade pattern
// (`TLSClient` / `DTLSClient` over `FacadeLock<Engine>`).
//
// Host: `FacadeLock<V>` IS `Synchronization.Mutex<V>` (byte-for-byte the same
// `init(_:)` and `withLock { … }` surface as the rest of the host orchestrator).
//
// Embedded: `Mutex` is not provided by `Synchronization`, so `FacadeLock<V>` is a
// `final class` holding the value behind a tiny test-and-test-and-set spinlock
// over `Atomic<Bool>`. `nonisolated(unsafe)` on the storage (NOT
// `@unchecked Sendable`) confines the unsafety to the storage member; the
// spinlock provides the mutual exclusion that makes the access safe. Embedded
// targets are typically single- or few-threaded, so contention is negligible;
// correctness (not throughput) is the goal.

#if !hasFeature(Embedded)
import Synchronization

/// On host the facade lock is the standard `Synchronization.Mutex`.
typealias FacadeLock<Value> = Mutex<Value>

#else
import Synchronization

/// Embedded facade lock: an `Atomic<Bool>` spinlock guarding the stored value.
/// `withLock` is non-throwing (every facade call site maps engine errors into a
/// `Result` *inside* the closure, so the closure itself never throws).
final class FacadeLock<Value>: Sendable {
    private let locked = Atomic<Bool>(false)
    private nonisolated(unsafe) var value: Value

    init(_ value: Value) {
        self.value = value
    }

    /// Runs `body` with exclusive access to the protected value.
    func withLock<R>(_ body: (inout Value) -> R) -> R {
        // Test-and-test-and-set acquire.
        while true {
            if locked.compareExchange(
                expected: false, desired: true, ordering: .acquiring
            ).exchanged {
                break
            }
        }
        defer { locked.store(false, ordering: .releasing) }
        return body(&value)
    }
}
#endif
