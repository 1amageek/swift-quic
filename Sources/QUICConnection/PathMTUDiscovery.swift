/// Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
///
/// Implements active path-MTU discovery per RFC 8899 and RFC 9000 §14.
/// The connection probes the path with padded ack-eliciting packets at increasing
/// sizes; on a probe ACK it raises the effective maximum packet size, and on probe
/// loss (or no ACK after PTO) it stops raising and, after repeated failure at the
/// base size, declares a black hole (RFC 8899 §5.3).

import Foundation
import Synchronization
import QUICCore

// MARK: - PMTU Discovery State

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

// MARK: - PMTU Probe

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

// MARK: - Path MTU Discovery

/// Per-path DPLPMTUD state machine (RFC 8899 / RFC 9000 §14).
///
/// This type only performs in-memory bookkeeping and arithmetic for the search
/// algorithm; it never performs I/O. It is therefore implemented with a `Mutex`
/// rather than an `actor` (see the project concurrency rules).
///
/// The owning connection drives it: it asks for the next probe size, builds and
/// sends a padded PING+PADDING packet at that size, then reports the probe's fate
/// (`onProbeAcknowledged` / `onProbeLost`). A probe loss MUST NOT be reported to
/// the congestion controller (RFC 9000 §14.4) — that is the caller's contract.
public final class PathMTUDiscovery: Sendable {

    // MARK: - Constants

    /// The base PLPMTU: the QUIC minimum maximum packet size (RFC 9000 §14.1, §8.1).
    /// Probing starts above this and never falls below it.
    public static let basePLPMTU: Int = 1200

    /// Maximum probe attempts at a given size before that size is abandoned
    /// (RFC 8899 §5.1.4, MAX_PROBES). A size that fails this many times is treated
    /// as not supported and the search converges below it.
    public static let maxProbes: Int = 3

    // MARK: - State

    private struct State: Sendable {
        /// Current search phase.
        var phase: PMTUDiscoveryPhase

        /// The current validated PLPMTU (largest acknowledged probe, or base).
        var currentPLPMTU: Int

        /// The effective search ceiling, clamped to the peer's max_udp_payload_size
        /// and the configured probe ceiling.
        var maxPLPMTU: Int

        /// The size of the probe currently outstanding (if any).
        var outstandingProbe: PMTUProbe?

        /// The size we are currently trying to validate (the next probe target).
        var probeTarget: Int

        /// Number of consecutive failed probe attempts at `probeTarget`.
        var probeCount: Int

        /// Number of consecutive failed probes at the base size (black-hole counter).
        var baseProbeFailures: Int
    }

    private let state: Mutex<State>

    // MARK: - Initialization

    /// Creates a DPLPMTUD state machine.
    ///
    /// - Parameters:
    ///   - enabled: Whether discovery is active. When false the PMTU stays at the base.
    ///   - maxProbeSize: The configured upper bound to probe to (search ceiling). Clamped
    ///     to be at least the base PLPMTU.
    public init(enabled: Bool, maxProbeSize: Int) {
        let ceiling = max(Self.basePLPMTU, maxProbeSize)
        self.state = Mutex(State(
            phase: enabled ? .base : .disabled,
            currentPLPMTU: Self.basePLPMTU,
            maxPLPMTU: ceiling,
            outstandingProbe: nil,
            probeTarget: Self.basePLPMTU,
            probeCount: 0,
            baseProbeFailures: 0
        ))
    }

    // MARK: - Configuration from the peer

    /// Applies the peer's `max_udp_payload_size` transport parameter as an additional
    /// ceiling on the search (RFC 9000 §14, §18.2). The effective ceiling becomes the
    /// minimum of the configured probe size and the peer's advertised limit, never below
    /// the base PLPMTU. Has no effect when discovery is disabled.
    ///
    /// - Parameter peerMaxUDPPayloadSize: The peer's advertised max_udp_payload_size.
    public func setPeerMaxUDPPayloadSize(_ peerMaxUDPPayloadSize: UInt64) {
        state.withLock { s in
            guard s.phase != .disabled else { return }
            // Clamp to a sane Int and never below the base PLPMTU.
            let peerLimit: Int
            if peerMaxUDPPayloadSize >= UInt64(Int.max) {
                peerLimit = Int.max
            } else {
                peerLimit = Int(peerMaxUDPPayloadSize)
            }
            let bounded = max(Self.basePLPMTU, min(s.maxPLPMTU, peerLimit))
            s.maxPLPMTU = bounded
            // If we already validated up to the new ceiling, the search is done.
            if s.currentPLPMTU >= s.maxPLPMTU {
                s.currentPLPMTU = min(s.currentPLPMTU, s.maxPLPMTU)
                s.phase = .searchComplete
                s.outstandingProbe = nil
            }
        }
    }

    // MARK: - Queries

    /// The current effective maximum packet size in bytes.
    ///
    /// This is the largest size the send path may use for ordinary packets. It is the
    /// base PLPMTU until a larger probe is acknowledged.
    public var currentMaxPacketSize: Int {
        state.withLock { $0.currentPLPMTU }
    }

    /// The current search phase.
    public var phase: PMTUDiscoveryPhase {
        state.withLock { $0.phase }
    }

    /// The effective search ceiling after peer/configuration clamping.
    public var effectiveCeiling: Int {
        state.withLock { $0.maxPLPMTU }
    }

    /// Whether a probe is currently outstanding (awaiting ACK or loss).
    public var hasOutstandingProbe: Bool {
        state.withLock { $0.outstandingProbe != nil }
    }

    /// Whether another probe should be sent now.
    ///
    /// Returns true only when discovery is enabled, the search has not converged or
    /// failed, there is headroom above the current PLPMTU, and no probe is already
    /// outstanding.
    public var shouldProbe: Bool {
        state.withLock { s in
            Self.shouldProbe(s)
        }
    }

    private static func shouldProbe(_ s: State) -> Bool {
        guard s.phase == .base || s.phase == .searching else { return false }
        guard s.outstandingProbe == nil else { return false }
        return s.maxPLPMTU > s.currentPLPMTU
    }

    // MARK: - Probe Generation

    /// Computes the next probe size to attempt, or `nil` if no probe should be sent.
    ///
    /// Uses an optimistic binary-search-style step toward the ceiling (RFC 8899 §5.3):
    /// the next target is the midpoint between the current validated PLPMTU and the
    /// ceiling. This is a pure computation; it does not record the probe — call
    /// `recordProbeSent(size:packetNumber:)` once the probe packet is actually sent.
    ///
    /// - Returns: The total datagram size to probe at, or `nil` to send no probe.
    public func nextProbeSize() -> Int? {
        state.withLock { s in
            guard Self.shouldProbe(s) else { return nil }
            return Self.computeProbeTarget(s)
        }
    }

    private static func computeProbeTarget(_ s: State) -> Int {
        // Optimistic binary search between the validated PLPMTU and the ceiling.
        let low = s.currentPLPMTU
        let high = s.maxPLPMTU
        let mid = low + (high - low) / 2
        // Ensure forward progress: a probe must be strictly larger than what is validated.
        return max(low + 1, mid)
    }

    /// Records that a probe of the given size was sent in the given packet.
    ///
    /// Transitions to `.searching` and marks the probe outstanding. The caller MUST
    /// have already padded the packet to `size` bytes with PING + PADDING so that an
    /// ACK validates the full path MTU.
    ///
    /// - Parameters:
    ///   - size: The total UDP datagram size of the probe.
    ///   - packetNumber: The application-space packet number carrying the probe.
    public func recordProbeSent(size: Int, packetNumber: UInt64) {
        state.withLock { s in
            guard s.phase == .base || s.phase == .searching else { return }
            s.phase = .searching
            s.probeTarget = size
            s.outstandingProbe = PMTUProbe(size: size, packetNumber: packetNumber)
        }
    }

    // MARK: - Probe Outcomes

    /// Handles acknowledgment of an outstanding probe (RFC 8899 §5.3).
    ///
    /// Raises the validated PLPMTU to the probe size and resumes searching upward, or
    /// converges if the ceiling has been reached. Acknowledgment of a packet that is
    /// not the outstanding probe is ignored.
    ///
    /// - Parameter packetNumber: The acknowledged packet number.
    /// - Returns: `true` if this acknowledged the outstanding probe and raised the PMTU.
    @discardableResult
    public func onProbeAcknowledged(packetNumber: UInt64) -> Bool {
        state.withLock { s in
            guard let probe = s.outstandingProbe, probe.packetNumber == packetNumber else {
                return false
            }
            // The probe of `probe.size` bytes reached the peer: validate it.
            s.currentPLPMTU = max(s.currentPLPMTU, probe.size)
            s.outstandingProbe = nil
            s.probeCount = 0
            s.baseProbeFailures = 0
            if s.currentPLPMTU >= s.maxPLPMTU {
                s.currentPLPMTU = min(s.currentPLPMTU, s.maxPLPMTU)
                s.phase = .searchComplete
            } else {
                s.phase = .searching
            }
            return true
        }
    }

    /// Handles loss (or PTO expiry without ACK) of an outstanding probe.
    ///
    /// RFC 9000 §14.4: a lost probe packet MUST NOT be treated as a congestion signal
    /// — the caller is responsible for not feeding it to the congestion controller.
    /// RFC 8899 §5.3/§5.1.4: after MAX_PROBES failures at a size the search converges
    /// below it; repeated failure at the base size declares a black hole.
    ///
    /// - Parameter packetNumber: The lost probe's packet number.
    /// - Returns: `true` if this matched the outstanding probe.
    @discardableResult
    public func onProbeLost(packetNumber: UInt64) -> Bool {
        state.withLock { s in
            guard let probe = s.outstandingProbe, probe.packetNumber == packetNumber else {
                return false
            }
            s.outstandingProbe = nil
            s.probeCount += 1

            // A probe above the base failing simply means that size is not supported.
            // Stop raising (converge at the current validated PLPMTU) without touching cwnd.
            if probe.size > Self.basePLPMTU {
                // After MAX_PROBES at this target, abandon the upward search.
                if s.probeCount >= Self.maxProbes {
                    s.phase = .searchComplete
                    s.probeCount = 0
                } else {
                    // Allow a retry at a (recomputed) target below the failed size.
                    s.maxPLPMTU = max(s.currentPLPMTU, probe.size - 1)
                    s.phase = s.maxPLPMTU > s.currentPLPMTU ? .searching : .searchComplete
                }
            } else {
                // Black-hole detection: base-size probes are not getting through.
                s.baseProbeFailures += 1
                if s.baseProbeFailures >= Self.maxProbes {
                    s.phase = .error
                    s.currentPLPMTU = Self.basePLPMTU
                }
            }
            return true
        }
    }

    /// Resets the search to the base PLPMTU, e.g. after connection migration / path change
    /// (RFC 8899 §5.4). Has no effect when discovery is disabled.
    public func reset() {
        state.withLock { s in
            guard s.phase != .disabled else { return }
            s.phase = .base
            s.currentPLPMTU = Self.basePLPMTU
            s.outstandingProbe = nil
            s.probeTarget = Self.basePLPMTU
            s.probeCount = 0
            s.baseProbeFailures = 0
        }
    }
}
