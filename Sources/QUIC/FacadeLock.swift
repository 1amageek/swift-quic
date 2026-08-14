// FacadeLock.swift
// The facade's value-protecting lock.
//
// The QUIC facade is "the caller that locks": `QUICEngineConnection` is a
// `final class & Sendable` that holds the value-type, sans-I/O
// `QUICConnectionEngine` behind this lock. The engine holds no lock and performs
// no I/O; the facade serializes every mutation before crossing an async boundary.
//
import Synchronization

/// Native, WASM, and Embedded use the same synchronization contract.
typealias FacadeLock<Value: ~Copyable> = Mutex<Value>
