// QUICEngineTimerOutput.swift
// The clock-free timer surface of the connection engine, mirroring DTLS's
// `DTLSFlightController` + `handleTimeout()`.
//
// The engine NEVER sleeps and NEVER reads a clock. Time enters ONLY as an
// injected `nowNanos: UInt64` parameter. After any step that can change a
// deadline (send, receive, timeout), the engine reports the single nearest
// absolute deadline (monotonic nanoseconds, same timeline as the injected
// `nowNanos`) for each timer it owns. The host facade computes the minimum,
// parks its `AsyncTimer.sleep(untilNanos:)` against it, and on wake calls
// `handleTimeout(nowNanos:)`. This is the critical Embedded unblock: it replaces
// `ContinuousClock` / `Task.sleep` inside the orchestrator.

import QUICWire

/// The kind of timer that elapsed, so the facade can attribute a fired deadline.
public enum QUICTimerKind: Sendable, Equatable, CaseIterable {
    /// PTO / loss-detection timer (RFC 9002 §6.2): retransmit or probe.
    case lossDetection
    /// ACK delay timer (RFC 9000 §13.2.1): an ACK is owed.
    case ackDelay
    /// Idle timeout (RFC 9000 §10.1): the connection is dead.
    case idle
    /// Path-validation timeout (RFC 9000 §8.2.4): a PATH_CHALLENGE expired.
    case pathValidation
    /// Pacing release (RFC 9002 §7.7): the pacer's next send instant.
    case pacing
}

/// The set of absolute deadlines the engine currently wants the facade to honor.
///
/// Each field is an absolute monotonic-nanoseconds instant on the SAME timeline
/// as the `nowNanos` the facade injects; `nil` means that timer is not armed. The
/// facade waits until ``earliestDeadlineNanos`` and then calls
/// `handleTimeout(nowNanos:)`.
public struct QUICEngineDeadlines: Sendable, Equatable {
    public var lossDetectionNanos: UInt64?
    public var ackDelayNanos: UInt64?
    public var idleNanos: UInt64?
    public var pathValidationNanos: UInt64?
    public var pacingNanos: UInt64?

    public init(
        lossDetectionNanos: UInt64? = nil,
        ackDelayNanos: UInt64? = nil,
        idleNanos: UInt64? = nil,
        pathValidationNanos: UInt64? = nil,
        pacingNanos: UInt64? = nil
    ) {
        self.lossDetectionNanos = lossDetectionNanos
        self.ackDelayNanos = ackDelayNanos
        self.idleNanos = idleNanos
        self.pathValidationNanos = pathValidationNanos
        self.pacingNanos = pacingNanos
    }

    /// The nearest armed deadline across all timers, or `nil` if none are armed.
    public var earliestDeadlineNanos: UInt64? {
        var best: UInt64? = nil
        for candidate in [lossDetectionNanos, ackDelayNanos, idleNanos, pathValidationNanos, pacingNanos] {
            guard let candidate else { continue }
            if let current = best {
                if candidate < current { best = candidate }
            } else {
                best = candidate
            }
        }
        return best
    }
}

/// What `handleTimeout(nowNanos:)` produced.
///
/// Like ``QUICEngineOutput`` it is pure data the facade acts on: protected
/// datagrams to send (retransmissions / probes / owed ACKs) and the recomputed
/// deadline set. `idleExpired` tells the facade the connection timed out and must
/// be torn down (no silent self-close inside the engine).
public struct QUICEngineTimerOutput: Sendable {
    /// Protected datagrams the facade must send (probes, retransmissions, ACKs).
    public var datagramsToSend: [[UInt8]]

    /// The timer kinds that fired in this call (for diagnostics / attribution).
    public var firedTimers: [QUICTimerKind]

    /// `true` when the idle timeout elapsed: the facade must close the connection.
    public var idleExpired: Bool

    /// `true` when path validation failed (challenge unanswered past its deadline).
    public var pathValidationFailed: Bool

    /// The recomputed deadline set after handling the timeout.
    public var deadlines: QUICEngineDeadlines

    public init(
        datagramsToSend: [[UInt8]] = [],
        firedTimers: [QUICTimerKind] = [],
        idleExpired: Bool = false,
        pathValidationFailed: Bool = false,
        deadlines: QUICEngineDeadlines = QUICEngineDeadlines()
    ) {
        self.datagramsToSend = datagramsToSend
        self.firedTimers = firedTimers
        self.idleExpired = idleExpired
        self.pathValidationFailed = pathValidationFailed
        self.deadlines = deadlines
    }
}
