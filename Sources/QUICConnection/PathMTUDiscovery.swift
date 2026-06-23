/// Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
///
/// Implements active path-MTU discovery per RFC 8899 and RFC 9000 §14.
/// The connection probes the path with padded ack-eliciting packets at increasing
/// sizes; on a probe ACK it raises the effective maximum packet size, and on probe
/// loss (or no ACK after PTO) it stops raising and, after repeated failure at the
/// base size, declares a black hole (RFC 8899 §5.3).
///
/// This is the host adapter: it holds the Embedded-clean ``PathMTUSearchCore`` value
/// type behind a `Mutex` (the search algorithm is pure in-memory arithmetic, so a
/// `Mutex` rather than an `actor` is correct per the project concurrency rules). The
/// public API and observable behaviour are identical to the previous in-class
/// implementation; the algorithm now lives in `QUICConnectionCore`.

import Synchronization
import QUICConnectionCore

// `PMTUDiscoveryPhase` and `PMTUProbe` are re-exported from QUICConnectionCore so
// existing call sites and tests that reference them via QUICConnection keep working.
@_exported import struct QUICConnectionCore.PMTUProbe
@_exported import enum QUICConnectionCore.PMTUDiscoveryPhase

// MARK: - Path MTU Discovery

/// Per-path DPLPMTUD state machine (RFC 8899 / RFC 9000 §14).
///
/// The owning connection drives it: it asks for the next probe size, builds and
/// sends a padded PING+PADDING packet at that size, then reports the probe's fate
/// (`onProbeAcknowledged` / `onProbeLost`). A probe loss MUST NOT be reported to
/// the congestion controller (RFC 9000 §14.4) — that is the caller's contract.
public final class PathMTUDiscovery: Sendable {

    // MARK: - Constants

    /// The base PLPMTU: the QUIC minimum maximum packet size (RFC 9000 §14.1, §8.1).
    public static let basePLPMTU: Int = PathMTUSearchCore.basePLPMTU

    /// Maximum probe attempts at a given size before that size is abandoned
    /// (RFC 8899 §5.1.4, MAX_PROBES).
    public static let maxProbes: Int = PathMTUSearchCore.maxProbes

    // MARK: - State

    /// The pure search state machine, serialised by this adapter's `Mutex`.
    private let core: Mutex<PathMTUSearchCore>

    // MARK: - Initialization

    /// Creates a DPLPMTUD state machine.
    ///
    /// - Parameters:
    ///   - enabled: Whether discovery is active. When false the PMTU stays at the base.
    ///   - maxProbeSize: The configured upper bound to probe to (search ceiling). Clamped
    ///     to be at least the base PLPMTU.
    public init(enabled: Bool, maxProbeSize: Int) {
        self.core = Mutex(PathMTUSearchCore(enabled: enabled, maxProbeSize: maxProbeSize))
    }

    // MARK: - Configuration from the peer

    /// Applies the peer's `max_udp_payload_size` transport parameter as an additional
    /// ceiling on the search (RFC 9000 §14, §18.2). Has no effect when disabled.
    ///
    /// - Parameter peerMaxUDPPayloadSize: The peer's advertised max_udp_payload_size.
    public func setPeerMaxUDPPayloadSize(_ peerMaxUDPPayloadSize: UInt64) {
        core.withLock { $0.setPeerMaxUDPPayloadSize(peerMaxUDPPayloadSize) }
    }

    // MARK: - Queries

    /// The current effective maximum packet size in bytes.
    public var currentMaxPacketSize: Int {
        core.withLock { $0.currentPLPMTU }
    }

    /// The current search phase.
    public var phase: PMTUDiscoveryPhase {
        core.withLock { $0.phase }
    }

    /// The effective search ceiling after peer/configuration clamping.
    public var effectiveCeiling: Int {
        core.withLock { $0.maxPLPMTU }
    }

    /// Whether a probe is currently outstanding (awaiting ACK or loss).
    public var hasOutstandingProbe: Bool {
        core.withLock { $0.hasOutstandingProbe }
    }

    /// Whether another probe should be sent now.
    public var shouldProbe: Bool {
        core.withLock { $0.shouldProbe }
    }

    // MARK: - Probe Generation

    /// Computes the next probe size to attempt, or `nil` if no probe should be sent.
    ///
    /// This is a pure computation; it does not record the probe — call
    /// `recordProbeSent(size:packetNumber:)` once the probe packet is actually sent.
    ///
    /// - Returns: The total datagram size to probe at, or `nil` to send no probe.
    public func nextProbeSize() -> Int? {
        core.withLock { $0.nextProbeSize() }
    }

    /// Records that a probe of the given size was sent in the given packet.
    ///
    /// The caller MUST have already padded the packet to `size` bytes with PING +
    /// PADDING so that an ACK validates the full path MTU.
    ///
    /// - Parameters:
    ///   - size: The total UDP datagram size of the probe.
    ///   - packetNumber: The application-space packet number carrying the probe.
    public func recordProbeSent(size: Int, packetNumber: UInt64) {
        core.withLock { $0.recordProbeSent(size: size, packetNumber: packetNumber) }
    }

    // MARK: - Probe Outcomes

    /// Handles acknowledgment of an outstanding probe (RFC 8899 §5.3).
    ///
    /// - Parameter packetNumber: The acknowledged packet number.
    /// - Returns: `true` if this acknowledged the outstanding probe and raised the PMTU.
    @discardableResult
    public func onProbeAcknowledged(packetNumber: UInt64) -> Bool {
        core.withLock { $0.onProbeAcknowledged(packetNumber: packetNumber) }
    }

    /// Handles loss (or PTO expiry without ACK) of an outstanding probe.
    ///
    /// RFC 9000 §14.4: a lost probe packet MUST NOT be treated as a congestion signal
    /// — the caller is responsible for not feeding it to the congestion controller.
    ///
    /// - Parameter packetNumber: The lost probe's packet number.
    /// - Returns: `true` if this matched the outstanding probe.
    @discardableResult
    public func onProbeLost(packetNumber: UInt64) -> Bool {
        core.withLock { $0.onProbeLost(packetNumber: packetNumber) }
    }

    /// Resets the search to the base PLPMTU, e.g. after connection migration / path change
    /// (RFC 8899 §5.4). Has no effect when discovery is disabled.
    public func reset() {
        core.withLock { $0.reset() }
    }
}
