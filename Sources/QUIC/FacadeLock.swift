// FacadeLock.swift
// The facade's value-protecting lock.
//
// The QUIC facade is "the caller that locks": `ManagedConnection` is a
// `final class & Sendable` that holds the value-type, sans-IO
// `QUICConnectionEngine` behind this lock, so its public methods are
// `Sendable`-safe. The engine itself holds no lock; the facade serialises every
// mutation here. This mirrors the proven swift-tls Tier-1 facade pattern
// (`TLSClient` / `DTLSClient` over `FacadeLock<Engine>`).
//
import Synchronization

/// Native, WASM, and Embedded use the same synchronization contract.
typealias FacadeLock<Value> = Mutex<Value>
