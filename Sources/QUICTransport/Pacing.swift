/// Pacing (RFC 9002 Section 7.7)
///
/// Pacing spreads packet transmission over time to avoid bursts
/// that can cause network congestion and packet loss.
///
/// Uses a token bucket algorithm where tokens accumulate at the
/// pacing rate and are consumed when sending packets.
///
/// ## Caller-locked core
///
/// The token-bucket math (including the 1.3.0 `Double`→`UInt64` overflow fix) lives
/// in the Embedded-clean value type `QUICRecoveryCore.PacerCore`. This class is the
/// host adapter: it keeps the `Mutex`, fixes a `ContinuousClock` epoch, converts
/// `Instant`/`Duration` to/from the monotonic `UInt64` nanoseconds the core consumes,
/// and computes the `Duration` delay (so the public API is byte-identical). Public
/// API and observable behavior are unchanged.

import Foundation
import Synchronization
import QUICRecoveryCore

// MARK: - Pacing Configuration

/// Configuration for packet pacing
public struct PacingConfiguration: Sendable {
    /// Initial pacing rate in bytes per second (0 = disabled)
    public var initialRate: UInt64

    /// Maximum burst size in bytes
    public var maxBurst: UInt64

    /// Minimum pacing interval
    public var minInterval: Duration

    /// Creates default pacing configuration
    public init() {
        // Start with 10 Mbps = 1.25 MB/s
        self.initialRate = 1_250_000
        // Allow bursts of up to 10 packets (~15KB)
        self.maxBurst = 15_000
        // Minimum 1ms between bursts
        self.minInterval = .milliseconds(1)
    }

    /// Creates custom pacing configuration
    public init(initialRate: UInt64, maxBurst: UInt64, minInterval: Duration) {
        self.initialRate = initialRate
        self.maxBurst = maxBurst
        self.minInterval = minInterval
    }

    /// Pacing disabled (no rate limiting)
    public static let disabled = PacingConfiguration(
        initialRate: 0,
        maxBurst: .max,
        minInterval: .zero
    )
}

// MARK: - Pacer

/// Token bucket pacer for rate-limited packet transmission
///
/// ## Usage
/// ```swift
/// let pacer = Pacer()
///
/// // Before sending a packet
/// if let delay = pacer.packetDelay(bytes: packetSize) {
///     try await Task.sleep(for: delay)
/// }
///
/// // After congestion feedback
/// pacer.updateRate(bytesPerSecond: newRate)
/// ```
public final class Pacer: Sendable {
    private let state: Mutex<PacerCore>

    /// Minimum pacing interval (host-only; participates in the `Duration` delay path).
    private let minInterval: Duration

    /// The epoch against which all `Instant`s are converted to monotonic nanos.
    private let epoch: ContinuousClock.Instant

    // MARK: - Initialization

    /// Creates a new pacer
    /// - Parameter config: Pacing configuration
    public init(config: PacingConfiguration = PacingConfiguration()) {
        let epoch = ContinuousClock.now
        self.epoch = epoch
        self.minInterval = config.minInterval
        self.state = Mutex(PacerCore(
            rate: config.initialRate,
            maxBurst: config.maxBurst,
            nowNanos: 0
        ))
    }

    // MARK: - Rate Control

    /// Updates the pacing rate
    ///
    /// Call this when congestion control adjusts the sending rate.
    ///
    /// - Parameter bytesPerSecond: New pacing rate (0 to disable)
    public func updateRate(bytesPerSecond: UInt64) {
        state.withLock { $0.updateRate(bytesPerSecond: bytesPerSecond) }
    }

    /// Updates the maximum burst size
    ///
    /// - Parameter bytes: Maximum burst size in bytes
    public func updateMaxBurst(bytes: UInt64) {
        state.withLock { $0.updateMaxBurst(bytes: bytes) }
    }

    // MARK: - Testing Seam

    /// Forces `lastUpdate` into the past to deterministically exercise the
    /// large-elapsed token-replenishment path (regression coverage for the
    /// `Double`→`UInt64` overflow trap). Test-only.
    internal func _setLastUpdateForTesting(secondsInPast: Double) {
        let nowNanos = currentNanos()
        let pastNanos = Self.nanos(of: .seconds(secondsInPast))
        let lastUpdate = nowNanos > pastNanos ? nowNanos - pastNanos : 0
        state.withLock { $0.setLastUpdate(nanos: lastUpdate) }
    }

    /// Current token count (test/diagnostics).
    public var currentTokens: UInt64 {
        state.withLock { $0.currentTokens }
    }

    // MARK: - Packet Scheduling

    /// Calculates delay before sending a packet
    ///
    /// This method:
    /// 1. Adds tokens based on elapsed time since last call
    /// 2. Checks if enough tokens are available
    /// 3. Returns delay needed if tokens are insufficient
    ///
    /// - Parameter bytes: Size of packet to send
    /// - Returns: Delay to wait, or nil if packet can be sent immediately
    public func packetDelay(bytes: UInt64) -> Duration? {
        let nowNanos = currentNanos()
        return state.withLock { core in
            switch core.schedule(bytes: bytes, nowNanos: nowNanos) {
            case .disabled, .immediate:
                return nil
            case .insufficient(let tokensNeeded):
                // Calculate time to wait for tokens (rate > 0 guaranteed by `schedule`).
                let secondsToWait = Double(tokensNeeded) / Double(core.rate)
                let delay = Duration.seconds(secondsToWait)
                // Enforce minimum interval
                if delay < minInterval {
                    return minInterval
                }
                return delay
            }
        }
    }

    /// Consumes tokens for a packet being sent
    ///
    /// Call this after sending a packet to account for the bytes.
    /// Use this when you need to track bytes separately from delay calculation.
    ///
    /// - Parameter bytes: Number of bytes sent
    public func consume(bytes: UInt64) {
        let nowNanos = currentNanos()
        state.withLock { $0.consume(bytes: bytes, nowNanos: nowNanos) }
    }

    // MARK: - State Queries

    /// Whether pacing is enabled
    public var isEnabled: Bool {
        state.withLock { $0.isEnabled }
    }

    /// Current pacing rate in bytes per second
    public var rate: UInt64 {
        state.withLock { $0.rate }
    }

    /// Available tokens (bytes that can be sent immediately)
    public var availableTokens: UInt64 {
        let nowNanos = currentNanos()
        return state.withLock { $0.availableTokens(nowNanos: nowNanos) }
    }

    /// Time until the next packet can be sent
    ///
    /// - Parameter bytes: Size of packet to send
    /// - Returns: Duration until packet can be sent, or zero if immediate
    public func timeUntilSend(bytes: UInt64) -> Duration {
        packetDelay(bytes: bytes) ?? .zero
    }

    // MARK: - Clock seam

    /// Current epoch-relative time in monotonic nanoseconds.
    private func currentNanos() -> UInt64 {
        Self.nanos(of: epoch.duration(to: ContinuousClock.now))
    }

    /// Converts a `Duration` to whole nanoseconds (negative clamps to 0), matching
    /// the host's `components`-based decomposition.
    @inline(__always)
    private static func nanos(of duration: Duration) -> UInt64 {
        let (seconds, attoseconds) = duration.components
        let ns = seconds * 1_000_000_000 + attoseconds / 1_000_000_000
        return ns < 0 ? 0 : UInt64(ns)
    }
}

// MARK: - Congestion Control Integration

extension Pacer {
    /// Updates pacing rate from congestion window and RTT
    ///
    /// RFC 9002 Section 7.7: N * congestion_window / smoothed_rtt
    ///
    /// - Parameters:
    ///   - congestionWindow: Current congestion window in bytes
    ///   - smoothedRTT: Smoothed round-trip time
    ///   - pacingGain: Pacing gain multiplier (typically 1.25 for BBR)
    public func updateFromCongestion(
        congestionWindow: UInt64,
        smoothedRTT: Duration,
        pacingGain: Double = 1.25
    ) {
        let rttSeconds = Double(smoothedRTT.components.seconds) +
                        Double(smoothedRTT.components.attoseconds) / 1e18

        guard rttSeconds > 0 else { return }

        let rate = UInt64(pacingGain * Double(congestionWindow) / rttSeconds)
        updateRate(bytesPerSecond: rate)
    }
}
