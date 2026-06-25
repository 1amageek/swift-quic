// QUICConnectionEngine+Timer.swift
// The clock-free timer surface (the QUIC analogue of DTLS's `DTLSFlightController`
// + `handleTimeout()`). The engine never sleeps and never reads a clock; the host
// facade owns the `AsyncTimer`, computes the nearest deadline from
// `deadlines(nowNanos:)`, parks against it, and on wake calls
// `handleTimeout(nowNanos:)`.

import QUICWire
import QUICConnectionCore
import QUICRecoveryCore

extension QUICConnectionEngine {
    // MARK: - Deadline reporting

    /// Reports the engine's current absolute deadline set (monotonic nanoseconds).
    ///
    /// The facade computes ``QUICEngineDeadlines/earliestDeadlineNanos`` and waits
    /// for it via `AsyncTimer.sleep(untilNanos:)`. Each deadline is `nil` when its
    /// timer is not armed.
    public func deadlines(nowNanos: UInt64) -> QUICEngineDeadlines {
        var result = QUICEngineDeadlines()

        // Loss-detection / PTO timer (RFC 9002 §6.2): armed when any space has an
        // ack-eliciting packet in flight. The deadline is oldest-sent + PTO,
        // backed off by 2^ptoCount.
        result.lossDetectionNanos = computeLossDetectionDeadline()

        // ACK delay timer (RFC 9000 §13.2.1): armed when an ack-eliciting packet
        // awaits acknowledgement; fires at receive-time + max_ack_delay.
        result.ackDelayNanos = computeAckDeadline()

        // Idle timeout (RFC 9000 §10.1).
        if config.idleTimeoutNanos > 0 {
            result.idleNanos = idleTimeout.nextDeadlineNanos()
        }

        // Path validation (RFC 9000 §8.2.4): the soonest pending challenge expiry.
        result.pathValidationNanos = nextPathValidationDeadline(nowNanos: nowNanos)

        // Pacing release (RFC 9002 §7.7): the congestion controller's next send
        // instant, when in the future.
        if let next = congestion.nextSendNanosOrImmediate, next > nowNanos {
            result.pacingNanos = next
        }

        return result
    }

    // MARK: - Timeout handling

    /// Drives all elapsed timers at `nowNanos` and returns what to send next plus
    /// the recomputed deadline set (clock-free, caller-driven).
    public mutating func handleTimeout(nowNanos: UInt64) throws(QUICEngineError) -> QUICEngineTimerOutput {
        var result = QUICEngineTimerOutput()
        guard status != .closed else {
            result.deadlines = deadlines(nowNanos: nowNanos)
            return result
        }

        // 1) Idle timeout — terminal (no silent self-close; the facade tears down).
        if config.idleTimeoutNanos > 0, idleTimeout.checkTimeout(nowNanos: nowNanos) {
            result.idleExpired = true
            result.firedTimers.append(.idle)
            result.deadlines = deadlines(nowNanos: nowNanos)
            return result
        }

        // 2) Loss detection (RFC 9002 §6.1/§6.2): detect time-threshold losses,
        // feed congestion control, and on PTO send a probe.
        var output = QUICEngineOutput()
        let lossFired = try detectAndHandleLosses(nowNanos: nowNanos)
        if lossFired { result.firedTimers.append(.lossDetection) }

        // 3) Path-validation timeouts.
        let expiredPaths = pathValidation.checkTimeouts(nowNanos: nowNanos)
        if !expiredPaths.isEmpty {
            result.pathValidationFailed = true
            result.firedTimers.append(.pathValidation)
        }

        // 4) An owed ACK whose delay has elapsed becomes immediately sendable.
        if computeAckDeadline().map({ $0 <= nowNanos }) == true {
            result.firedTimers.append(.ackDelay)
        }

        // Assemble everything we now want to send.
        try flushPending(nowNanos: nowNanos, into: &output)
        result.datagramsToSend = output.datagramsToSend
        result.deadlines = deadlines(nowNanos: nowNanos)
        return result
    }

    // MARK: - Private

    private mutating func detectAndHandleLosses(nowNanos: UInt64) throws(QUICEngineError) -> Bool {
        var anyLoss = false
        let latestRTT = rtt.latestRTTNanos
        let smoothedRTT = rtt.smoothedRTTNanos
        let snapshot = RTTSnapshot(hasEstimate: latestRTT > 0, smoothedRTTNanos: smoothedRTT)

        for level in [EncryptionLevel.initial, .handshake, .application] {
            let lossResult = withSpace(level) { sp in
                sp.lossDetector.detectLostPackets(
                    nowNanos: nowNanos,
                    latestRTTNanos: latestRTT,
                    smoothedRTTNanos: smoothedRTT)
            }
            if !lossResult.lost.isEmpty {
                anyLoss = true
                let lostPackets = lossResult.lost.map {
                    CongestionPacket(sentBytes: $0.sentBytes, timeSentNanos: $0.timeSentNanos, inFlight: $0.inFlight)
                }
                congestion.onPacketsLost(packets: lostPackets, nowNanos: nowNanos, rtt: snapshot)
            }
        }

        // PTO: if no losses but a space still has ack-eliciting packets in flight
        // and the PTO deadline has passed, bump the PTO count and send a probe.
        if let ptoDeadline = computeLossDetectionDeadline(), ptoDeadline <= nowNanos {
            ptoCount += 1
            anyLoss = true
            // The actual probe (PING) is queued so flushPending sends an
            // ack-eliciting packet (RFC 9002 §6.2.4).
            queuePing()
        }

        return anyLoss
    }

    /// Queues a PING at the lowest level with keys + in-flight data so a PTO probe
    /// elicits an ACK.
    private mutating func queuePing() {
        let level = currentSendLevel
        // Mark the space ack-eliciting-pending so flush emits at least a PING.
        // We model this by enqueueing a synthetic empty CRYPTO-less PING via the
        // path-response-style direct queue: simplest is to ensure a frame is
        // produced. Use a stream-independent PING by adding to pendingDatagrams is
        // wrong; instead set a pending-ping flag honored in collectFrames.
        pendingPing[level] = true
    }

    private func computeLossDetectionDeadline() -> UInt64? {
        // The PTO is armed only when there is ack-eliciting data in flight in at
        // least one non-discarded space. The deadline is the oldest unacked
        // ack-eliciting send time + PTO (backed off by 2^ptoCount).
        var oldest: UInt64? = nil
        for sp in [initialSpace, handshakeSpace, applicationSpace] where !sp.isDiscarded {
            guard sp.lossDetector.ackElicitingInFlight > 0 else { continue }
            if let p = sp.lossDetector.oldestUnackedPackets(count: 1).first {
                if let cur = oldest { oldest = min(cur, p.timeSentNanos) } else { oldest = p.timeSentNanos }
            }
        }
        guard let oldest else { return nil }
        let basePTO = rtt.probeTimeoutNanos(maxAckDelayNanos: config.maxAckDelayNanos)
        let backoff = UInt64(1) << UInt64(min(ptoCount, 20))
        let (scaled, overflow) = basePTO.multipliedReportingOverflow(by: backoff)
        let pto = overflow ? UInt64.max : scaled
        let (deadline, dOverflow) = oldest.addingReportingOverflow(pto)
        return dOverflow ? UInt64.max : deadline
    }

    private func computeAckDeadline() -> UInt64? {
        var soonest: UInt64? = nil
        for sp in [initialSpace, handshakeSpace, applicationSpace] where !sp.isDiscarded {
            guard sp.ackElicitingPending, let recvAt = sp.ackDeadlineNanos else { continue }
            let deadline = recvAt &+ config.maxAckDelayNanos
            if let cur = soonest { soonest = min(cur, deadline) } else { soonest = deadline }
        }
        return soonest
    }

    private func nextPathValidationDeadline(nowNanos: UInt64) -> UInt64? {
        // PathValidationCore tracks per-path challenge sent times; the soonest
        // expiry is sentAt + validationTimeout. The core exposes checkTimeouts but
        // not a direct deadline accessor in this slice, so we conservatively arm
        // the timer at now + validationTimeout when any validation is pending.
        pathValidation.validatedPaths.isEmpty && pathValidationPending
            ? nowNanos &+ config.pathValidationTimeoutNanos
            : nil
    }
}
