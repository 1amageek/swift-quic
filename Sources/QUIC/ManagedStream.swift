/// Managed Stream
///
/// High-level stream wrapper implementing QUICStreamProtocol.
/// Provides async read/write operations for application data.
///
/// Host-only QUIC orchestrator spine (Foundation/`Synchronization`). Gated
/// `#if !hasFeature(Embedded)` so the `QUIC` target compiles under Embedded with
/// only the cores + the `[UInt8]` engine facade (quic Slice C).

#if !hasFeature(Embedded) && !os(WASI)

import Foundation
import Synchronization

// MARK: - Managed Stream

/// A managed QUIC stream implementing QUICStreamProtocol.
///
/// Concurrency invariants:
/// - `state` is the sole mutable stream state and every access uses the same
///   `Mutex` on every target where this host-only type exists.
/// - The parent owns its streams, so the back-reference is weak to prevent a
///   retain cycle. It is assigned only during initialization; runtime weak
///   zeroing is the only subsequent mutation.
/// - Each operation promotes the weak reference to a strong local before use,
///   keeping the parent alive for the complete operation.
/// - No I/O, suspension, or external callback occurs while `state` is locked.
///
/// Swift cannot prove the weak-reference contract, so Sendable conformance is
/// checked manually at this boundary. The weak reference and Mutex never exist
/// in the Embedded/WASI engine-only build.
public final class ManagedStream: @unchecked Sendable {
    // MARK: - Properties

    /// The stream ID
    public let id: UInt64

    /// Whether this is a unidirectional stream
    public let isUnidirectional: Bool

    /// Weak reference to parent connection
    private nonisolated(unsafe) weak var connection: ManagedConnection?

    /// Internal state
    private let state: Mutex<ManagedStreamState>

    // MARK: - Initialization

    /// Creates a managed stream
    /// - Parameters:
    ///   - id: The stream ID
    ///   - connection: Parent connection
    ///   - isUnidirectional: Whether unidirectional
    init(
        id: UInt64,
        connection: ManagedConnection,
        isUnidirectional: Bool
    ) {
        self.id = id
        self.connection = connection
        self.isUnidirectional = isUnidirectional
        self.state = Mutex(ManagedStreamState())
    }

    // MARK: - Computed Properties

    /// Whether this is a bidirectional stream
    public var isBidirectional: Bool {
        !isUnidirectional
    }
}

// MARK: - QUICStreamProtocol

extension ManagedStream: QUICStreamProtocol {
    public func read() async throws -> Data {
        try await readMaximum(nil)
    }

    public func read(maxBytes: Int) async throws -> Data {
        guard maxBytes > 0 else {
            throw ManagedStreamError.invalidReadSize(maxBytes)
        }
        return try await readMaximum(maxBytes)
    }

    public func write(_ data: Data) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard !state.withLock({ $0.writeClosed || $0.writeTerminationInProgress }) else {
            throw ManagedStreamError.streamClosed
        }

        try conn.writeToStream(id, data: data)
    }

    public func closeWrite() async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard try beginWriteTermination() else { return }
        do {
            try conn.finishStream(id)
            completeWriteTermination()
        } catch {
            cancelWriteTermination()
            throw error
        }
    }

    public func reset(errorCode: UInt64) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard try beginWriteTermination() else { return }
        do {
            try conn.resetStream(id, errorCode: errorCode)
            completeWriteTermination()
        } catch {
            cancelWriteTermination()
            throw error
        }
    }

    public func reset(
        errorCode: UInt64,
        reliablyDelivering reliableSize: UInt64
    ) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard try beginWriteTermination() else { return }
        do {
            try conn.resetStreamAt(
                id,
                errorCode: errorCode,
                reliableSize: reliableSize
            )
            completeWriteTermination()
        } catch {
            cancelWriteTermination()
            throw error
        }
    }

    public func stopSending(errorCode: UInt64) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        conn.stopSending(id, errorCode: errorCode)
        state.withLock { $0.readClosed = true }
    }

    private func beginWriteTermination() throws -> Bool {
        try state.withLock { state in
            if state.writeClosed {
                return false
            }
            guard !state.writeTerminationInProgress else {
                throw ManagedStreamError.concurrentWriteTermination
            }
            state.writeTerminationInProgress = true
            return true
        }
    }

    private func completeWriteTermination() {
        state.withLock { state in
            state.writeTerminationInProgress = false
            state.writeClosed = true
        }
    }

    private func cancelWriteTermination() {
        state.withLock { $0.writeTerminationInProgress = false }
    }

    private func readMaximum(_ maximum: Int?) async throws -> Data {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        let buffered: Data? = try state.withLock { state in
            guard !state.readClosed else {
                throw ManagedStreamError.streamClosed
            }
            guard !state.isReading else {
                throw ManagedStreamError.concurrentRead
            }
            if !state.pendingRead.isEmpty {
                return Self.takePrefix(maximum, from: &state.pendingRead)
            }
            state.isReading = true
            return nil
        }
        if let buffered {
            return buffered
        }

        do {
            let received = try await conn.readFromStream(id)
            return state.withLock { state in
                state.isReading = false
                state.pendingRead = received
                return Self.takePrefix(maximum, from: &state.pendingRead)
            }
        } catch {
            state.withLock { $0.isReading = false }
            throw error
        }
    }

    private static func takePrefix(
        _ maximum: Int?,
        from buffer: inout Data
    ) -> Data {
        guard let maximum, buffer.count > maximum else {
            let result = buffer
            buffer.removeAll(keepingCapacity: true)
            return result
        }
        let result = Data(buffer.prefix(maximum))
        buffer.removeFirst(maximum)
        return result
    }
}

// MARK: - Internal State

private struct ManagedStreamState: Sendable {
    var readClosed: Bool = false
    var writeClosed: Bool = false
    var writeTerminationInProgress: Bool = false
    var isReading: Bool = false
    var pendingRead = Data()
}

// MARK: - Errors

/// Errors from ManagedStream operations
public enum ManagedStreamError: Error, Sendable {
    /// Parent connection was lost
    case connectionLost

    /// Stream is closed
    case streamClosed

    /// Write failed
    case writeFailed(String)

    /// Read failed
    case readFailed(String)

    /// A read was requested while another read was suspended.
    case concurrentRead

    /// A FIN or reset operation is already committing the write-side state.
    case concurrentWriteTermination

    /// The maximum read size must be positive.
    case invalidReadSize(Int)
}

#endif
