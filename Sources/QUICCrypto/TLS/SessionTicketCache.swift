/// QUIC session-ticket storage independent of the TLS protocol implementation.

import Foundation
import Synchronization

/// Thread-safe client-side cache for opaque TLS resumption values.
///
/// The cache owns no TLS state machine and performs no key derivation. A
/// canonical provider may consume the value during session construction; a
/// provider that does not expose resumption rejects late configuration with a
/// typed error.
public final class ClientSessionCache: Sendable {
    public struct CachedSession: Sendable, Hashable {
        public let ticket: SessionTicketData
        public let serverIdentity: String
        public let createdAt: Date

        public init(
            ticket: SessionTicketData,
            serverIdentity: String,
            createdAt: Date = Date()
        ) {
            self.ticket = ticket
            self.serverIdentity = serverIdentity
            self.createdAt = createdAt
        }

        public var sessionTicketData: SessionTicketData { ticket }
        public var maxEarlyDataSize: UInt32 { ticket.maxEarlyDataSize }
        public var supportsEarlyData: Bool { maxEarlyDataSize > 0 }

        public func isValid(at date: Date = Date()) -> Bool {
            guard ticket.lifetime > 0 else { return false }
            let elapsed = date.timeIntervalSince(createdAt)
            return elapsed >= 0 && elapsed < Double(ticket.lifetime)
        }
    }

    private struct State: Sendable {
        var sessions: [String: [CachedSession]] = [:]
    }

    private let state = Mutex(State())
    private let maxSessionsPerServer: Int

    public init(maxSessionsPerServer: Int = 4) {
        precondition(maxSessionsPerServer > 0)
        self.maxSessionsPerServer = maxSessionsPerServer
    }

    public func store(session: CachedSession, for serverIdentity: String) {
        state.withLock { state in
            var sessions = state.sessions[serverIdentity, default: []]
            sessions.removeAll { !$0.isValid() }
            sessions.append(session)
            if sessions.count > maxSessionsPerServer {
                sessions.removeFirst(sessions.count - maxSessionsPerServer)
            }
            state.sessions[serverIdentity] = sessions
        }
    }

    public func store(ticket: SessionTicketData, for serverIdentity: String) {
        store(
            session: CachedSession(ticket: ticket, serverIdentity: serverIdentity),
            for: serverIdentity
        )
    }

    public func retrieve(for serverIdentity: String) -> CachedSession? {
        state.withLock { state in
            var sessions = state.sessions[serverIdentity, default: []]
            sessions.removeAll { !$0.isValid() }
            state.sessions[serverIdentity] = sessions
            return sessions.last
        }
    }

    public func retrieveForEarlyData(for serverIdentity: String) -> CachedSession? {
        state.withLock { state in
            var sessions = state.sessions[serverIdentity, default: []]
            sessions.removeAll { !$0.isValid() }
            state.sessions[serverIdentity] = sessions
            return sessions.last { $0.supportsEarlyData }
        }
    }

    public func remove(for serverIdentity: String) {
        _ = state.withLock { $0.sessions.removeValue(forKey: serverIdentity) }
    }

    public func clear() {
        state.withLock { $0.sessions.removeAll() }
    }
}
