/// Embedded-clean NewReno congestion controller (RFC 9002 §7) as a value type.
///
/// This is the byte-identical math of the host `NewRenoCongestionController`,
/// expressed as a `struct` with `mutating` methods. Time is injected as a monotonic
/// `UInt64` nanosecond value (`nowNanos` / `timeSentNanos`); the controller never
/// reads a clock. The host adapter holds a `Mutex<NewRenoCore>`, reads its
/// `ContinuousClock`, converts to nanoseconds, and calls these methods under the
/// lock — observable behavior is unchanged.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.
public struct NewRenoCore: Sendable {

    // MARK: - RFC 9002 §7.1 State Variables

    /// Current congestion window in bytes.
    public private(set) var congestionWindow: Int

    /// Slow-start threshold in bytes.
    public private(set) var ssthresh: Int

    /// Recovery start time (injected monotonic nanos), or nil when not in recovery.
    public private(set) var recoveryStartNanos: UInt64?

    /// Accumulated acked bytes used by the AIMD estimator.
    private var bytesAcked: Int

    // MARK: - Pacing state

    /// Next send time as injected monotonic nanos.
    public private(set) var nextSendNanos: UInt64

    /// Pacing rate in bytes per nanosecond.
    private var pacingRate: Double

    /// Remaining burst tokens.
    private var burstTokens: Int

    // MARK: - Configuration

    /// Maximum datagram size; may be raised by DPLPMTUD.
    private var maxDatagramSize: Int

    /// Minimum congestion window floor.
    private var minimumWindow: Int

    // MARK: - Initialization

    /// Creates a NewReno controller core (RFC 9002 §7.2 initial window).
    public init(maxDatagramSize: Int = CongestionCoreConstants.maxDatagramSize) {
        let minimumWindow = CongestionCoreConstants.minimumWindow(maxDatagramSize: maxDatagramSize)
        let initialWindow = CongestionCoreConstants.initialWindow(maxDatagramSize: maxDatagramSize)
        self.congestionWindow = initialWindow
        self.ssthresh = Int.max
        self.recoveryStartNanos = nil
        self.bytesAcked = 0
        self.nextSendNanos = 0
        self.pacingRate = 0
        self.burstTokens = CongestionCoreConstants.initialBurstTokens
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = minimumWindow
    }

    // MARK: - State Queries

    /// The current congestion-control phase.
    public var state: CongestionCoreState {
        if let start = recoveryStartNanos {
            return .recovery(startNanos: start)
        } else if congestionWindow < ssthresh {
            return .slowStart
        } else {
            return .congestionAvoidance
        }
    }

    /// Available window for sending given bytes currently in flight.
    public func availableWindow(bytesInFlight: Int) -> Int {
        max(0, congestionWindow - bytesInFlight)
    }

    /// The next pacing send time in nanos, or nil if a packet can be sent now.
    public var nextSendNanosOrImmediate: UInt64? {
        if burstTokens > 0 { return nil }
        if pacingRate <= 0 { return nil }
        return nextSendNanos
    }

    // MARK: - Event Handlers

    /// Records a packet send and advances the pacing clock (RFC 9002 §7.7).
    public mutating func onPacketSent(bytes: Int, nowNanos: UInt64) {
        if burstTokens > 0 {
            burstTokens -= 1
        } else if pacingRate > 0 {
            let intervalNanos = Double(bytes) / pacingRate
            let nanos = Int64(intervalNanos)
            nextSendNanos = nowNanos &+ UInt64(bitPattern: nanos)
        }
    }

    /// Processes acknowledged packets, growing the window per phase.
    public mutating func onPacketsAcknowledged(
        packets: [CongestionPacket],
        rtt: RTTSnapshot
    ) {
        for packet in packets {
            guard packet.inFlight else { continue }

            if let recoveryStart = recoveryStartNanos {
                if packet.timeSentNanos <= recoveryStart {
                    continue
                }
                recoveryStartNanos = nil
            }

            if congestionWindow < ssthresh {
                // Slow start: exponential growth.
                congestionWindow += packet.sentBytes
            } else {
                // Congestion avoidance: AIMD.
                bytesAcked += packet.sentBytes
                if bytesAcked >= congestionWindow {
                    congestionWindow += maxDatagramSize
                    bytesAcked = 0
                }
            }
        }

        updatePacingRate(rtt: rtt)
    }

    /// Processes detected losses (RFC 9002 §7.3.2: one reduction per RTT).
    public mutating func onPacketsLost(
        packets: [CongestionPacket],
        nowNanos: UInt64,
        rtt: RTTSnapshot
    ) {
        guard !packets.isEmpty else { return }
        if recoveryStartNanos != nil { return }
        enterRecovery(nowNanos: nowNanos)
        updatePacingRate(rtt: rtt)
    }

    /// Treats an ECN-CE mark the same as packet loss.
    public mutating func onECNCongestionEvent(nowNanos: UInt64) {
        if recoveryStartNanos != nil { return }
        enterRecovery(nowNanos: nowNanos)
    }

    /// Collapses the window and re-enters slow start (RFC 9002 §7.6.2).
    public mutating func onPersistentCongestion() {
        congestionWindow = minimumWindow
        ssthresh = Int.max
        bytesAcked = 0
        recoveryStartNanos = nil
        burstTokens = CongestionCoreConstants.initialBurstTokens
        pacingRate = 0
    }

    /// Raises the tracked datagram size / minimum-window floor (RFC 9000 §14).
    public mutating func updateMaxDatagramSize(_ maxDatagramSize: Int) {
        guard maxDatagramSize > self.maxDatagramSize else { return }
        self.maxDatagramSize = maxDatagramSize
        self.minimumWindow = 2 * maxDatagramSize
    }

    // MARK: - Debug

    /// A compact diagnostic string mirroring the host description.
    public var description: String {
        let stateStr: String
        if recoveryStartNanos != nil {
            stateStr = "recovery"
        } else if congestionWindow < ssthresh {
            stateStr = "slow_start"
        } else {
            stateStr = "congestion_avoidance"
        }
        return "NewReno(cwnd=\(congestionWindow), ssthresh=\(ssthresh), state=\(stateStr))"
    }

    // MARK: - Private helpers

    private mutating func enterRecovery(nowNanos: UInt64) {
        recoveryStartNanos = nowNanos
        let reducedWindow = Int(Double(congestionWindow) * CongestionCoreConstants.lossReductionFactor)
        ssthresh = max(reducedWindow, minimumWindow)
        congestionWindow = ssthresh
        bytesAcked = 0
    }

    private mutating func updatePacingRate(rtt: RTTSnapshot) {
        guard rtt.hasEstimate else { return }
        let smoothedNanos = rtt.smoothedRTTNanos
        if smoothedNanos > 0 {
            pacingRate = Double(congestionWindow) / Double(smoothedNanos)
        }
    }
}
