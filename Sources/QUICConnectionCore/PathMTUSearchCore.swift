/// Embedded-clean DPLPMTUD search core (RFC 8899 / RFC 9000 §14).
///
/// `PathMTUSearchCore` is the pure value-type state machine for active path-MTU
/// discovery: it performs only in-memory bookkeeping and integer arithmetic for
/// the search algorithm and never touches I/O, time, crypto, or `Data`. The host
/// adapter (`PathMTUDiscovery`) holds one of these behind a `Mutex` and forwards
/// each call; coring the value type keeps the concurrency primitive adapter-side
/// (per the project rules) while making the algorithm Embedded-buildable.
///
/// Behaviour is byte-identical to the former in-class implementation: the same
/// optimistic-binary-search probe target, the same MAX_PROBES convergence, and the
/// same base-size black-hole detection.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`,
/// no crypto; typed throws are unnecessary as every operation is total.

/// The DPLPMTUD search phase (RFC 8899 §5.2).
public enum PMTUDiscoveryPhase: Sendable, Equatable {
    /// Discovery is disabled by configuration. The PMTU stays at the base value.
    case disabled

    /// Operating at the base PLPMTU (`QUIC_MIN`, 1200). No probe is outstanding and
    /// the search has not started (or has been reset after a black hole).
    case base

    /// Actively searching upward: a probe is or will be outstanding at `probeSize`.
    case searching

    /// The search has converged: no further probing until the path changes.
    case searchComplete

    /// A black hole was detected at the base size (RFC 8899 §5.3): even base-size
    /// packets are not getting through. The PMTU is pinned to the base value.
    case error
}

/// A description of an outstanding PMTU probe.
public struct PMTUProbe: Sendable, Equatable {
    /// The total UDP datagram size, in bytes, this probe was sent at.
    public let size: Int

    /// The packet number the probe was carried in (application packet number space).
    public let packetNumber: UInt64

    public init(size: Int, packetNumber: UInt64) {
        self.size = size
        self.packetNumber = packetNumber
    }
}

/// The pure DPLPMTUD search state machine. A `struct`: all mutation is in-place on
/// the caller-held value; the adapter serialises access with its own `Mutex`.
public struct PathMTUSearchCore: Sendable {

    // MARK: - Constants

    /// The base PLPMTU: the QUIC minimum maximum packet size (RFC 9000 §14.1, §8.1).
    /// Probing starts above this and never falls below it.
    public static let basePLPMTU: Int = 1200

    /// Maximum probe attempts at a given size before that size is abandoned
    /// (RFC 8899 §5.1.4, MAX_PROBES).
    public static let maxProbes: Int = 3

    // MARK: - State

    /// Current search phase.
    public private(set) var phase: PMTUDiscoveryPhase

    /// The current validated PLPMTU (largest acknowledged probe, or base).
    public private(set) var currentPLPMTU: Int

    /// The effective search ceiling, clamped to the peer's max_udp_payload_size
    /// and the configured probe ceiling.
    public private(set) var maxPLPMTU: Int

    /// The size of the probe currently outstanding (if any).
    public private(set) var outstandingProbe: PMTUProbe?

    /// The size we are currently trying to validate (the next probe target).
    public private(set) var probeTarget: Int

    /// Number of consecutive failed probe attempts at `probeTarget`.
    private var probeCount: Int

    /// Number of consecutive failed probes at the base size (black-hole counter).
    private var baseProbeFailures: Int

    // MARK: - Initialization

    /// Creates a DPLPMTUD search state.
    ///
    /// - Parameters:
    ///   - enabled: Whether discovery is active. When false the PMTU stays at the base.
    ///   - maxProbeSize: The configured upper bound to probe to (search ceiling). Clamped
    ///     to be at least the base PLPMTU.
    public init(enabled: Bool, maxProbeSize: Int) {
        let ceiling = max(Self.basePLPMTU, maxProbeSize)
        self.phase = enabled ? .base : .disabled
        self.currentPLPMTU = Self.basePLPMTU
        self.maxPLPMTU = ceiling
        self.outstandingProbe = nil
        self.probeTarget = Self.basePLPMTU
        self.probeCount = 0
        self.baseProbeFailures = 0
    }

    // MARK: - Configuration from the peer

    /// Applies the peer's `max_udp_payload_size` transport parameter as an additional
    /// ceiling on the search (RFC 9000 §14, §18.2). Has no effect when disabled.
    public mutating func setPeerMaxUDPPayloadSize(_ peerMaxUDPPayloadSize: UInt64) {
        guard phase != .disabled else { return }
        let peerLimit: Int
        if peerMaxUDPPayloadSize >= UInt64(Int.max) {
            peerLimit = Int.max
        } else {
            peerLimit = Int(peerMaxUDPPayloadSize)
        }
        let bounded = max(Self.basePLPMTU, min(maxPLPMTU, peerLimit))
        maxPLPMTU = bounded
        if currentPLPMTU >= maxPLPMTU {
            currentPLPMTU = min(currentPLPMTU, maxPLPMTU)
            phase = .searchComplete
            outstandingProbe = nil
        }
    }

    // MARK: - Queries

    /// Whether a probe is currently outstanding (awaiting ACK or loss).
    public var hasOutstandingProbe: Bool {
        outstandingProbe != nil
    }

    /// Whether another probe should be sent now.
    public var shouldProbe: Bool {
        guard phase == .base || phase == .searching else { return false }
        guard outstandingProbe == nil else { return false }
        return maxPLPMTU > currentPLPMTU
    }

    // MARK: - Probe Generation

    /// Computes the next probe size to attempt, or `nil` if no probe should be sent.
    ///
    /// Uses an optimistic binary-search-style step toward the ceiling (RFC 8899 §5.3).
    /// Pure: it does not record the probe — call `recordProbeSent` once the probe is sent.
    public func nextProbeSize() -> Int? {
        guard shouldProbe else { return nil }
        return computeProbeTarget()
    }

    private func computeProbeTarget() -> Int {
        // Optimistic binary search between the validated PLPMTU and the ceiling.
        let low = currentPLPMTU
        let high = maxPLPMTU
        let mid = low + (high - low) / 2
        // Ensure forward progress: a probe must be strictly larger than what is validated.
        return max(low + 1, mid)
    }

    /// Records that a probe of the given size was sent in the given packet.
    public mutating func recordProbeSent(size: Int, packetNumber: UInt64) {
        guard phase == .base || phase == .searching else { return }
        phase = .searching
        probeTarget = size
        outstandingProbe = PMTUProbe(size: size, packetNumber: packetNumber)
    }

    // MARK: - Probe Outcomes

    /// Handles acknowledgment of an outstanding probe (RFC 8899 §5.3).
    ///
    /// - Returns: `true` if this acknowledged the outstanding probe and raised the PMTU.
    @discardableResult
    public mutating func onProbeAcknowledged(packetNumber: UInt64) -> Bool {
        guard let probe = outstandingProbe, probe.packetNumber == packetNumber else {
            return false
        }
        // The probe of `probe.size` bytes reached the peer: validate it.
        currentPLPMTU = max(currentPLPMTU, probe.size)
        outstandingProbe = nil
        probeCount = 0
        baseProbeFailures = 0
        if currentPLPMTU >= maxPLPMTU {
            currentPLPMTU = min(currentPLPMTU, maxPLPMTU)
            phase = .searchComplete
        } else {
            phase = .searching
        }
        return true
    }

    /// Handles loss (or PTO expiry without ACK) of an outstanding probe.
    ///
    /// RFC 9000 §14.4: a lost probe MUST NOT be treated as a congestion signal — that
    /// is the caller's contract. RFC 8899 §5.3/§5.1.4: after MAX_PROBES failures at a
    /// size the search converges below it; repeated failure at the base size declares
    /// a black hole.
    ///
    /// - Returns: `true` if this matched the outstanding probe.
    @discardableResult
    public mutating func onProbeLost(packetNumber: UInt64) -> Bool {
        guard let probe = outstandingProbe, probe.packetNumber == packetNumber else {
            return false
        }
        outstandingProbe = nil
        probeCount += 1

        // A probe above the base failing simply means that size is not supported.
        if probe.size > Self.basePLPMTU {
            if probeCount >= Self.maxProbes {
                phase = .searchComplete
                probeCount = 0
            } else {
                maxPLPMTU = max(currentPLPMTU, probe.size - 1)
                phase = maxPLPMTU > currentPLPMTU ? .searching : .searchComplete
            }
        } else {
            // Black-hole detection: base-size probes are not getting through.
            baseProbeFailures += 1
            if baseProbeFailures >= Self.maxProbes {
                phase = .error
                currentPLPMTU = Self.basePLPMTU
            }
        }
        return true
    }

    /// Resets the search to the base PLPMTU, e.g. after path change (RFC 8899 §5.4).
    /// Has no effect when discovery is disabled.
    public mutating func reset() {
        guard phase != .disabled else { return }
        phase = .base
        currentPLPMTU = Self.basePLPMTU
        outstandingProbe = nil
        probeTarget = Self.basePLPMTU
        probeCount = 0
        baseProbeFailures = 0
    }
}
