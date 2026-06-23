/// Path Validation for Connection Migration (RFC 9000 Section 9.3)
///
/// Path validation is used to verify reachability after a change in address.
/// An endpoint validates a path by sending a PATH_CHALLENGE frame and receiving
/// a PATH_RESPONSE frame containing the same data.
///
/// This is the host adapter over the Embedded-clean value type
/// `QUICConnectionCore.PathValidationCore`. It keeps the `Mutex`, fixes a
/// `ContinuousClock` epoch, owns the RNG (`ConnectionSecureRandom`) that generates
/// the 8-byte PATH_CHALLENGE data, converts `Instant`/`Duration` to/from monotonic
/// nanoseconds, and bridges `Data`/`Frame` at the boundary. Anti-spoofing
/// (fail-closed match) and anti-amplification budgeting live in the core, so
/// observable behavior is identical to the prior implementation.

import Foundation
import Synchronization
import QUICCore
import QUICConnectionCore

// MARK: - Path Validation State

/// State of a path validation attempt
public enum PathValidationState: Sendable {
    /// Validation not started
    case initial

    /// Challenge sent, waiting for response
    case pending(challengeData: Data, sentAt: ContinuousClock.Instant)

    /// Path validated successfully
    case validated(at: ContinuousClock.Instant)

    /// Validation failed (timeout or other error)
    case failed(reason: String)
}

/// Represents a network path (local + remote address pair).
/// Re-exported from the Embedded-clean core so the wire/value type is shared.
public typealias NetworkPath = PathValidationCore.NetworkPath

// MARK: - Path Validation Manager

/// Manages path validation for connection migration
public final class PathValidationManager: Sendable {

    private let state: Mutex<PathValidationCore>

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    /// Size in bytes of a PATH_RESPONSE frame on the wire: 1 type byte + 8 data bytes
    /// (RFC 9000 §19.18). Used to charge the response against the anti-amplification budget.
    public static let pathResponseFrameSize: UInt64 = PathValidationCore.pathResponseFrameSize

    /// Timeout for path validation (RFC 9000 recommends 3 * PTO)
    public let validationTimeout: Duration

    // MARK: - Initialization

    public init(validationTimeout: Duration = .seconds(3)) {
        let epoch = ContinuousClock.now
        self.epoch = epoch
        self.validationTimeout = validationTimeout
        self.state = Mutex(PathValidationCore(validationTimeoutNanos: Self.nanos(of: validationTimeout)))
    }

    // MARK: - Initiating Validation

    /// Starts path validation for a new path
    /// - Parameter path: The network path to validate
    /// - Returns: PATH_CHALLENGE frame data (8 bytes random)
    public func startValidation(for path: NetworkPath) -> Data {
        // RNG lives in the adapter; the core stores the supplied challenge bytes.
        let challengeData = generateChallengeData()
        let nowNanos = currentNanos()
        state.withLock { $0.startValidation(challengeData: [UInt8](challengeData), for: path, nowNanos: nowNanos) }
        return challengeData
    }

    /// Generates a PATH_CHALLENGE frame for a path
    /// - Parameter path: The path to validate
    /// - Returns: The PATH_CHALLENGE frame
    public func createChallengeFrame(for path: NetworkPath) -> Frame {
        let data = startValidation(for: path)
        // The PATH_CHALLENGE payload is `[UInt8]` in the Embedded-clean Frame enum;
        // this path validator tracks challenge data as `Data`, so convert here.
        return .pathChallenge([UInt8](data))
    }

    // MARK: - Processing Received Frames

    /// Processes a received PATH_CHALLENGE on a specific path, honoring the anti-amplification
    /// budget for unvalidated paths (RFC 9000 §8.2.1).
    ///
    /// RFC 9000 §8.2.1: "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame
    /// ... [and] An endpoint MUST NOT send more than three times ... until it has validated the
    /// peer's address." A PATH_RESPONSE for an unvalidated path therefore counts against that
    /// path's amplification budget, and the response is sent on the path it arrived on.
    ///
    /// - Parameters:
    ///   - data: The 8-byte challenge data.
    ///   - path: The network path the PATH_CHALLENGE arrived on.
    ///   - remainingAmplificationBudget: Bytes still permitted to be sent toward `path` before
    ///     it is validated. Pass `UInt64.max` for a validated path (no limit).
    /// - Returns: The PATH_RESPONSE frame to send on `path`, or `nil` if the amplification budget
    ///   is exhausted. When `nil`, the response is recorded as pending so it can be emitted later
    ///   once more credit is available; it is never silently dropped.
    public func handleChallenge(
        _ data: Data,
        on path: NetworkPath,
        remainingAmplificationBudget: UInt64
    ) -> Frame? {
        let payload = state.withLock {
            $0.handleChallenge([UInt8](data), on: path, remainingAmplificationBudget: remainingAmplificationBudget)
        }
        guard let payload else { return nil }
        // PATH_RESPONSE payload is `[UInt8]` in the Embedded-clean Frame enum.
        return .pathResponse(payload)
    }

    /// Processes a received PATH_CHALLENGE without a path/budget context.
    ///
    /// Convenience for paths that are already validated or otherwise not amplification-limited.
    /// Always returns the PATH_RESPONSE frame. Prefer `handleChallenge(_:on:remainingAmplificationBudget:)`
    /// for unvalidated paths so the response is charged against the amplification budget.
    /// - Parameter data: The 8-byte challenge data
    /// - Returns: PATH_RESPONSE frame to send back
    public func handleChallenge(_ data: Data) -> Frame {
        // RFC 9000: MUST respond with PATH_RESPONSE containing identical data
        let payload = state.withLock { $0.handleChallenge([UInt8](data)) }
        // PATH_RESPONSE payload is `[UInt8]` in the Embedded-clean Frame enum.
        return .pathResponse(payload)
    }

    /// Processes a received PATH_RESPONSE
    /// - Parameter data: The 8-byte response data
    /// - Returns: The validated path if this completes a validation, nil otherwise
    public func handleResponse(_ data: Data) -> NetworkPath? {
        let nowNanos = currentNanos()
        return state.withLock { $0.handleResponse([UInt8](data), nowNanos: nowNanos) }
    }

    // MARK: - Query State

    /// Checks if a path is validated
    public func isValidated(_ path: NetworkPath) -> Bool {
        state.withLock { $0.isValidated(path) }
    }

    /// Gets the validation state for a path
    public func validationState(for path: NetworkPath) -> PathValidationState? {
        state.withLock { core in
            guard let coreState = core.validationState(for: path) else { return nil }
            switch coreState {
            case .initial:
                return .initial
            case .pending(let challengeData, let sentAtNanos):
                return .pending(challengeData: Data(challengeData), sentAt: Self.instant(from: epoch, nanos: sentAtNanos))
            case .validated(let atNanos):
                return .validated(at: Self.instant(from: epoch, nanos: atNanos))
            case .failed(let reason):
                switch reason {
                case .timeout:
                    return .failed(reason: "timeout")
                }
            }
        }
    }

    /// Gets all validated paths
    public var validatedPaths: Set<NetworkPath> {
        Set(state.withLock { $0.validatedPaths })
    }

    /// Gets and clears pending responses (challenges we received but have not yet responded to,
    /// e.g. because the anti-amplification budget was exhausted when they arrived).
    /// - Returns: The challenge-data values still awaiting a PATH_RESPONSE.
    public func getPendingResponses() -> [Data] {
        state.withLock { $0.takePendingResponses().map { Data($0) } }
    }

    /// Gets and clears pending responses together with the path each arrived on.
    /// - Returns: Pairs of (challenge data, path) still awaiting a PATH_RESPONSE.
    public func getPendingResponsesWithPaths() -> [(data: Data, path: NetworkPath?)] {
        state.withLock { core in
            core.takePendingResponsesWithPaths().map { (data: Data($0.data), path: $0.path) }
        }
    }

    // MARK: - Timeout Handling

    /// Checks for timed-out validations and marks them as failed
    /// - Returns: Paths that failed due to timeout
    public func checkTimeouts() -> [NetworkPath] {
        let nowNanos = currentNanos()
        return state.withLock { $0.checkTimeouts(nowNanos: nowNanos) }
    }

    /// Retries validation for a path that timed out
    /// - Parameter path: The path to retry
    /// - Returns: New challenge data, or nil if path wasn't in failed state
    public func retryValidation(for path: NetworkPath) -> Data? {
        // RNG lives in the adapter; only commit the new challenge if the core accepts the retry.
        let challengeData = generateChallengeData()
        let nowNanos = currentNanos()
        let accepted = state.withLock {
            $0.retryValidation(challengeData: [UInt8](challengeData), for: path, nowNanos: nowNanos)
        }
        return accepted ? challengeData : nil
    }

    // MARK: - Private Helpers

    /// Generates random 8-byte challenge data
    private func generateChallengeData() -> Data {
        ConnectionSecureRandom.bytes(count: 8)
    }

    // MARK: - Clock seam

    /// Current epoch-relative time in monotonic nanoseconds.
    private func currentNanos() -> UInt64 {
        Self.nanos(of: epoch.duration(to: ContinuousClock.now))
    }

    /// Converts a `Duration` to whole nanoseconds (negative clamps to 0).
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

// MARK: - Connection ID Manager

/// Manages connection ID lifecycle for connection migration
public final class ConnectionIDManager: Sendable {

    private let state = Mutex<CIDState>(CIDState())

    private struct CIDState: Sendable {
        /// Our issued connection IDs (sequence number -> CID info)
        var issuedCIDs: [UInt64: IssuedConnectionID] = [:]

        /// Next sequence number for issuing new CIDs
        var nextSequenceNumber: UInt64 = 0

        /// Peer's connection IDs we can use
        var peerCIDs: [UInt64: PeerConnectionID] = [:]

        /// Current active peer CID (for sending)
        var activePeerCID: ConnectionID?

        /// Retired sequence numbers
        var retiredSequences: Set<UInt64> = []
    }

    /// Info about a CID we issued
    public struct IssuedConnectionID: Sendable {
        public let connectionID: ConnectionID
        public let sequenceNumber: UInt64
        public let statelessResetToken: Data
        public let issuedAt: ContinuousClock.Instant
        public var isRetired: Bool
    }

    /// Info about a peer's CID
    public struct PeerConnectionID: Sendable {
        public let connectionID: ConnectionID
        public let sequenceNumber: UInt64
        public let statelessResetToken: Data
        public let receivedAt: ContinuousClock.Instant
    }

    /// Maximum number of active CIDs (from transport parameters)
    public let activeConnectionIDLimit: UInt64

    // MARK: - Initialization

    public init(activeConnectionIDLimit: UInt64 = 2) {
        self.activeConnectionIDLimit = activeConnectionIDLimit
    }

    // MARK: - Issuing Connection IDs

    /// Issues a new connection ID
    /// - Parameter length: Length of the CID (0-20 bytes, default 8)
    /// - Returns: NEW_CONNECTION_ID frame to send
    /// - Throws: If the length is invalid or frame creation fails
    public func issueNewConnectionID(length: Int = 8) throws -> NewConnectionIDFrame {
        return try state.withLock { s in
            guard let cid = ConnectionID.random(length: length) else {
                throw ConnectionIDError.invalidLength(length)
            }
            let token = generateStatelessResetToken()
            let seq = s.nextSequenceNumber
            s.nextSequenceNumber += 1

            let issued = IssuedConnectionID(
                connectionID: cid,
                sequenceNumber: seq,
                statelessResetToken: token,
                issuedAt: .now,
                isRetired: false
            )
            s.issuedCIDs[seq] = issued

            return try NewConnectionIDFrame(
                sequenceNumber: seq,
                retirePriorTo: 0,
                connectionID: cid,
                statelessResetToken: token
            )
        }
    }

    /// Errors related to connection ID operations
    public enum ConnectionIDError: Error, Sendable {
        /// Invalid connection ID length
        case invalidLength(Int)
        /// Duplicate sequence number with different CID or token (RFC 9000 §5.1.1)
        case duplicateSequenceNumber(sequenceNumber: UInt64)
        /// Exceeded active_connection_id_limit
        case exceededConnectionIDLimit(limit: UInt64, current: Int)
    }

    /// Gets all active (non-retired) issued CIDs
    public var activeIssuedCIDs: [IssuedConnectionID] {
        state.withLock { s in
            s.issuedCIDs.values.filter { !$0.isRetired }
        }
    }

    // MARK: - Processing Peer CIDs

    /// Processes a NEW_CONNECTION_ID frame from peer
    /// - Parameter frame: The received frame
    /// - Throws: ConnectionIDError if validation fails
    public func handleNewConnectionID(_ frame: NewConnectionIDFrame) throws {
        try state.withLock { s in
            // RFC 9000 §5.1.1: Check for duplicate sequence number
            // If same sequence but different CID or token, it's a PROTOCOL_VIOLATION
            if let existing = s.peerCIDs[frame.sequenceNumber] {
                // If CID and token match exactly, just ignore the duplicate
                if existing.connectionID == frame.connectionID &&
                   existing.statelessResetToken == frame.statelessResetToken {
                    return  // Ignore exact duplicate
                }
                // Different CID or token with same sequence = PROTOCOL_VIOLATION
                throw ConnectionIDError.duplicateSequenceNumber(
                    sequenceNumber: frame.sequenceNumber
                )
            }

            // Retire CIDs as requested by retire_prior_to.
            //
            // RFC 9000 §19.15 guarantees `retire_prior_to <= sequence_number` (enforced at
            // decode by NewConnectionIDFrame's validating init), so this value is already
            // bounded. We additionally bound the work to the connection IDs we actually hold
            // rather than iterating `0..<retire_prior_to`: a long-lived connection can
            // legitimately reach a very large sequence number, and iterating the attacker- or
            // peer-supplied numeric range would be O(retire_prior_to) regardless of how few
            // CIDs we store. Iterating the held set is O(stored CIDs), which is itself capped
            // by active_connection_id_limit.
            let sequencesToRetire = s.peerCIDs.keys.filter { $0 < frame.retirePriorTo }
            for seq in sequencesToRetire {
                s.peerCIDs.removeValue(forKey: seq)
                s.retiredSequences.insert(seq)
            }

            // RFC 9000 §5.1.1: Enforce active_connection_id_limit
            // Count active (non-retired) CIDs
            let activeCIDCount = s.peerCIDs.count
            if activeCIDCount >= Int(activeConnectionIDLimit) {
                // We're at or over the limit - peer is violating our limit
                throw ConnectionIDError.exceededConnectionIDLimit(
                    limit: activeConnectionIDLimit,
                    current: activeCIDCount + 1  // +1 for the new CID they're trying to add
                )
            }

            // Store new CID
            let peerCID = PeerConnectionID(
                connectionID: frame.connectionID,
                sequenceNumber: frame.sequenceNumber,
                statelessResetToken: Data(frame.statelessResetToken),
                receivedAt: .now
            )
            s.peerCIDs[frame.sequenceNumber] = peerCID

            // Update active CID if needed
            if s.activePeerCID == nil {
                s.activePeerCID = frame.connectionID
            }
        }
    }

    /// Processes a RETIRE_CONNECTION_ID frame from peer
    /// - Parameter sequenceNumber: The sequence number to retire
    /// - Returns: The retired CID info, or nil if not found
    public func handleRetireConnectionID(_ sequenceNumber: UInt64) -> IssuedConnectionID? {
        return state.withLock { s in
            guard var cid = s.issuedCIDs[sequenceNumber] else {
                return nil
            }
            cid.isRetired = true
            s.issuedCIDs[sequenceNumber] = cid
            return cid
        }
    }

    // MARK: - Using Peer CIDs

    /// Gets the current active peer CID for sending
    public var activePeerConnectionID: ConnectionID? {
        state.withLock { $0.activePeerCID }
    }

    /// Switches to a different peer CID (for connection migration)
    /// - Parameter sequenceNumber: The sequence number of the CID to use
    /// - Returns: true if switch was successful
    public func switchToConnectionID(sequenceNumber: UInt64) -> Bool {
        return state.withLock { s in
            guard let peerCID = s.peerCIDs[sequenceNumber] else {
                return false
            }
            s.activePeerCID = peerCID.connectionID
            return true
        }
    }

    /// Gets all available peer CIDs
    public var availablePeerCIDs: [PeerConnectionID] {
        state.withLock { Array($0.peerCIDs.values) }
    }

    // MARK: - Retirement

    /// Retires a peer CID (we should send RETIRE_CONNECTION_ID)
    /// - Parameter sequenceNumber: The sequence number to retire
    /// - Returns: RETIRE_CONNECTION_ID frame, or nil if not found
    public func retirePeerConnectionID(sequenceNumber: UInt64) -> Frame? {
        return state.withLock { s in
            guard s.peerCIDs.removeValue(forKey: sequenceNumber) != nil else {
                return nil
            }
            s.retiredSequences.insert(sequenceNumber)
            return .retireConnectionID(sequenceNumber)
        }
    }

    // MARK: - Private Helpers

    /// Generates a random 16-byte stateless reset token
    private func generateStatelessResetToken() -> Data {
        ConnectionSecureRandom.bytes(count: 16)
    }
}
