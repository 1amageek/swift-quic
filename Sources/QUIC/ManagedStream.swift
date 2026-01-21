/// Managed Stream
///
/// High-level stream wrapper implementing QUICStreamProtocol.
/// Provides async read/write operations for application data.

import Foundation
import Synchronization

// MARK: - Managed Stream

/// A managed QUIC stream implementing QUICStreamProtocol
public final class ManagedStream: @unchecked Sendable {
    // MARK: - Properties

    /// The stream ID
    public let id: UInt64

    /// Whether this is a unidirectional stream
    public let isUnidirectional: Bool

    /// Weak reference to parent connection
    private weak var connection: ManagedConnection?

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
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard !state.withLock({ $0.readClosed }) else {
            throw ManagedStreamError.streamClosed
        }

        return try await conn.readFromStream(id)
    }

    public func read(maxBytes: Int) async throws -> Data {
        let data = try await read()

        // Truncate if needed
        if data.count > maxBytes {
            return data.prefix(maxBytes)
        }
        return data
    }

    public func write(_ data: Data) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        guard !state.withLock({ $0.writeClosed }) else {
            throw ManagedStreamError.streamClosed
        }

        try conn.writeToStream(id, data: data)
    }

    public func closeWrite() async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        // Idempotent: only finish stream once
        let alreadyClosed = state.withLock { s in
            let was = s.writeClosed
            s.writeClosed = true
            return was
        }

        guard !alreadyClosed else { return }
        try conn.finishStream(id)
    }

    public func reset(errorCode: UInt64) async {
        guard let conn = connection else { return }

        state.withLock { state in
            state.writeClosed = true
            state.readClosed = true
        }
        conn.resetStream(id, errorCode: errorCode)
    }

    public func stopSending(errorCode: UInt64) async throws {
        guard let conn = connection else {
            throw ManagedStreamError.connectionLost
        }

        state.withLock { $0.readClosed = true }
        conn.stopSending(id, errorCode: errorCode)
    }
}

// MARK: - Internal State

private struct ManagedStreamState: Sendable {
    var readClosed: Bool = false
    var writeClosed: Bool = false
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
}
