/// Embedded-clean path-validation core (RFC 9000 §8.2 / §9.3) as a value type.
///
/// This is the byte-identical path-validation logic of the host
/// `PathValidationManager`, expressed as a `struct` operating purely on `[UInt8]`
/// challenge data and monotonic `UInt64` nanosecond timestamps. The host
/// `PathValidationManager` keeps a `Mutex`, a `ContinuousClock` epoch, and the RNG;
/// it generates challenge data, converts `Instant`/`Duration` to/from nanoseconds,
/// and delegates the matching/state logic here, so observable behavior is unchanged.
///
/// Anti-spoofing (fail-closed): a path is validated ONLY by a PATH_RESPONSE whose
/// 8 bytes exactly match a challenge we sent. A non-matching response validates
/// nothing and is reported as "no match" — never silently accepted.
///
/// Anti-amplification (RFC 9000 §8.2.1): a PATH_RESPONSE for an unvalidated path is
/// only emitted when the remaining budget covers the 9-byte frame; otherwise the
/// response is deferred (recorded), never dropped.
///
/// The host uses dictionaries keyed by `Data`/`NetworkPath`; this core uses small
/// arrays scanned by exact-byte / value equality, which preserves the identical
/// match semantics while staying Embedded-clean (no custom-Hashable dictionaries).
///
/// Embedded-clean: no Foundation, no `Data`, no `ContinuousClock`, no `any`,
/// no `Mutex`.
public struct PathValidationCore: Sendable {

    // MARK: - Public Value Types

    /// A network path (local + remote address pair). Mirrors the adapter's
    /// `NetworkPath`; equality is value equality over both address strings.
    public struct NetworkPath: Hashable, Sendable {
        public let localAddress: String
        public let remoteAddress: String

        public init(localAddress: String, remoteAddress: String) {
            self.localAddress = localAddress
            self.remoteAddress = remoteAddress
        }
    }

    /// State of a path validation attempt. Timestamps are epoch-relative nanoseconds.
    public enum ValidationState: Sendable, Equatable {
        /// Validation not started.
        case initial
        /// Challenge sent, waiting for response (8-byte challenge + send time in ns).
        case pending(challengeData: [UInt8], sentAtNanos: UInt64)
        /// Path validated successfully (validation time in ns).
        case validated(atNanos: UInt64)
        /// Validation failed (timeout or other error).
        case failed(reason: FailureReason)
    }

    /// Reason a validation failed. Closed enum so the adapter can map without strings.
    public enum FailureReason: Sendable, Equatable {
        case timeout
    }

    /// A challenge we received that still needs a PATH_RESPONSE, paired with the
    /// path it arrived on (RFC 9000 §8.2.1: the response is sent on that path).
    public struct PendingResponse: Sendable, Equatable {
        public let data: [UInt8]
        public let path: NetworkPath?

        public init(data: [UInt8], path: NetworkPath?) {
            self.data = data
            self.path = path
        }
    }

    // MARK: - Constants

    /// Size in bytes of a PATH_RESPONSE frame on the wire: 1 type byte + 8 data
    /// bytes (RFC 9000 §19.18). Charged against the anti-amplification budget.
    public static let pathResponseFrameSize: UInt64 = 9

    // MARK: - State

    /// Per-path validation state (path -> state). Scanned by path equality.
    private var validations: [(path: NetworkPath, state: ValidationState)]

    /// Challenges we've sent, mapped to the path being validated. Scanned by exact
    /// challenge-byte equality on PATH_RESPONSE (fail-closed matching).
    private var challenges: [(data: [UInt8], path: NetworkPath)]

    /// Successfully validated paths.
    private var validated: [NetworkPath]

    /// Challenges received that still need a PATH_RESPONSE (deferred responses).
    private var pendingResponses: [PendingResponse]

    /// Validation timeout in nanoseconds (RFC 9000 recommends 3 * PTO).
    public let validationTimeoutNanos: UInt64

    // MARK: - Initialization

    /// Creates a path-validation core.
    /// - Parameter validationTimeoutNanos: Validation timeout in nanoseconds.
    public init(validationTimeoutNanos: UInt64) {
        self.validations = []
        self.challenges = []
        self.validated = []
        self.pendingResponses = []
        self.validationTimeoutNanos = validationTimeoutNanos
    }

    // MARK: - Initiating Validation

    /// Starts validation for a path with caller-supplied 8-byte challenge data
    /// (RNG lives in the adapter). Records the challenge as pending and maps it to
    /// the path for later exact-match.
    ///
    /// - Parameters:
    ///   - challengeData: The 8 random challenge bytes (caller/RNG-supplied).
    ///   - path: The network path being validated.
    ///   - nowNanos: Current epoch-relative time in nanoseconds.
    public mutating func startValidation(
        challengeData: [UInt8],
        for path: NetworkPath,
        nowNanos: UInt64
    ) {
        setValidationState(.pending(challengeData: challengeData, sentAtNanos: nowNanos), for: path)
        challenges.append((data: challengeData, path: path))
    }

    // MARK: - Processing Received Frames

    /// Processes a received PATH_CHALLENGE on a specific path, honoring the
    /// anti-amplification budget for unvalidated paths (RFC 9000 §8.2.1).
    ///
    /// - Parameters:
    ///   - data: The 8-byte challenge data.
    ///   - path: The network path the PATH_CHALLENGE arrived on.
    ///   - remainingAmplificationBudget: Bytes still permitted toward `path` before
    ///     it is validated. Pass `UInt64.max` for a validated path (no limit).
    /// - Returns: The 8-byte PATH_RESPONSE payload to echo on `path`, or `nil` if
    ///   the budget is exhausted (the response is recorded as pending, not dropped).
    public mutating func handleChallenge(
        _ data: [UInt8],
        on path: NetworkPath,
        remainingAmplificationBudget: UInt64
    ) -> [UInt8]? {
        let isValidated = validated.contains(path)
        // A validated path is not subject to the anti-amplification limit.
        if isValidated || remainingAmplificationBudget >= Self.pathResponseFrameSize {
            return data
        }
        // Budget exhausted: defer the response (with its path), never drop it.
        pendingResponses.append(PendingResponse(data: data, path: path))
        return nil
    }

    /// Processes a received PATH_CHALLENGE without a path/budget context.
    /// Records the response as pending (path nil) and always returns the echo.
    /// - Parameter data: The 8-byte challenge data.
    /// - Returns: The 8-byte PATH_RESPONSE payload to echo back.
    public mutating func handleChallenge(_ data: [UInt8]) -> [UInt8] {
        pendingResponses.append(PendingResponse(data: data, path: nil))
        return data
    }

    /// Processes a received PATH_RESPONSE. Fail-closed: validates a path ONLY when
    /// the 8 bytes exactly match a challenge we sent.
    /// - Parameters:
    ///   - data: The 8-byte response data.
    ///   - nowNanos: Current epoch-relative time in nanoseconds.
    /// - Returns: The validated path if this completes a validation, `nil` otherwise.
    public mutating func handleResponse(_ data: [UInt8], nowNanos: UInt64) -> NetworkPath? {
        guard let index = challenges.firstIndex(where: { $0.data == data }) else {
            // Response doesn't match any pending challenge - validate nothing.
            return nil
        }
        let path = challenges[index].path
        challenges.remove(at: index)

        setValidationState(.validated(atNanos: nowNanos), for: path)
        if !validated.contains(path) {
            validated.append(path)
        }
        return path
    }

    // MARK: - Query State

    /// Whether a path is validated.
    public func isValidated(_ path: NetworkPath) -> Bool {
        validated.contains(path)
    }

    /// The validation state for a path, or `nil` if unknown.
    public func validationState(for path: NetworkPath) -> ValidationState? {
        validations.first(where: { $0.path == path })?.state
    }

    /// All validated paths.
    public var validatedPaths: [NetworkPath] {
        validated
    }

    /// Drains and returns the deferred PATH_RESPONSE payloads (challenge data only).
    public mutating func takePendingResponses() -> [[UInt8]] {
        let responses = pendingResponses.map { $0.data }
        pendingResponses.removeAll()
        return responses
    }

    /// Drains and returns the deferred PATH_RESPONSEs with their arrival paths.
    public mutating func takePendingResponsesWithPaths() -> [PendingResponse] {
        let responses = pendingResponses
        pendingResponses.removeAll()
        return responses
    }

    // MARK: - Timeout Handling

    /// Marks timed-out pending validations as failed and removes their challenges.
    /// - Parameter nowNanos: Current epoch-relative time in nanoseconds.
    /// - Returns: Paths that failed due to timeout.
    public mutating func checkTimeouts(nowNanos: UInt64) -> [NetworkPath] {
        var failedPaths: [NetworkPath] = []

        for i in validations.indices {
            if case .pending(let data, let sentAtNanos) = validations[i].state {
                // `now - sentAt > timeout`, computed in unsigned ns. Guard against a
                // clock that has not advanced past sentAt (elapsed would be 0).
                let elapsed = nowNanos >= sentAtNanos ? nowNanos - sentAtNanos : 0
                if elapsed > validationTimeoutNanos {
                    let path = validations[i].path
                    validations[i].state = .failed(reason: .timeout)
                    removeChallenge(matching: data)
                    failedPaths.append(path)
                }
            }
        }

        return failedPaths
    }

    /// Retries a timed-out path with caller-supplied fresh 8-byte challenge data.
    /// - Parameters:
    ///   - challengeData: The new 8 random challenge bytes (caller/RNG-supplied).
    ///   - path: The path to retry.
    ///   - nowNanos: Current epoch-relative time in nanoseconds.
    /// - Returns: `true` if the path was in the failed state and was re-armed,
    ///   `false` otherwise (the caller should not have consumed RNG bytes).
    public mutating func retryValidation(
        challengeData: [UInt8],
        for path: NetworkPath,
        nowNanos: UInt64
    ) -> Bool {
        guard let state = validationState(for: path), case .failed = state else {
            return false
        }
        setValidationState(.pending(challengeData: challengeData, sentAtNanos: nowNanos), for: path)
        challenges.append((data: challengeData, path: path))
        return true
    }

    // MARK: - Private Helpers

    /// Sets (inserts or updates) the validation state for a path.
    private mutating func setValidationState(_ state: ValidationState, for path: NetworkPath) {
        if let index = validations.firstIndex(where: { $0.path == path }) {
            validations[index].state = state
        } else {
            validations.append((path: path, state: state))
        }
    }

    /// Removes the first challenge whose bytes match `data`.
    private mutating func removeChallenge(matching data: [UInt8]) {
        if let index = challenges.firstIndex(where: { $0.data == data }) {
            challenges.remove(at: index)
        }
    }
}
