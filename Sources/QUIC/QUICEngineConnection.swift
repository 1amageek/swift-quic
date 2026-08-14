// QUICEngineConnection.swift
// The seam-driven driver that rewires the QUIC connection orchestration onto the
// cored, sans-IO `QUICConnectionEngine<C, T>` (milestone M11, "quic Slice B").
//
// This is the QUIC analogue of the proven swift-tls Tier-1 facade
// (`TLSClient`/`DTLSClient` over `FacadeLock<Engine>`). It is a
// `final class & Sendable` that:
//
//   * holds the value-type engine behind a `FacadeLock` (the facade is "the
//     caller that locks"; the engine itself holds no lock and performs no I/O),
//   * inverts I/O onto the `DatagramTransport` seam — it receives owning
//     datagrams, borrows them for `engine.receive(...)`, and sends
//     the engine's produced datagrams via `transport.send(...)`, and
//   * drives timers through the `AsyncTimer` seam — after each engine step it
//     reads `engine.deadlines(nowNanos:)`, parks `AsyncTimer.sleep(untilNanos:)`
//     against the earliest deadline, and on wake calls
//     `engine.handleTimeout(nowNanos:)` and sends its outputs.
//
// There is no `ContinuousClock`, `Task.sleep`, or `Date` here: the timeline and
// wait both come from the injected `AsyncTimer`.
// Both seams are Embedded-clean (no `any`, no Foundation, no NIO), so this driver
// is dual-build: it compiles as an ordinary host type and under Embedded Swift.
//
// This is the canonical public driver used by `QUICClient` and
// `QUICServerConnection`; there is no legacy host facade or fallback path.

import _Concurrency   // REQUIRED under Embedded for AsyncStream/Task/withTaskGroup
import Synchronization
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICConnectionEngineCore
import QUICTLS
import TLSTypes
import NetworkingCore
import NetworkingDatagram
import NetworkingTime

/// A QUIC connection driven by the cored sans-IO engine over the
/// `DatagramTransport` + `AsyncTimer` seams.
///
/// `Transport` is the UDP datagram seam and `Timer` the monotonic-clock + sleep
/// seam. The driver owns the run loop; the
/// embedder injects the transport + timer (host: NIO/POSIX transport +
/// `ContinuousClock`-backed timer; Embedded: a POSIX transport + a POSIX timer or
/// the embedder's own executor-backed `AsyncTimer`).
public typealias QUICHandshakeHandler = @Sendable (
    HandshakeChunk
) async throws(QUICConnectionDriverError) -> Void

/// Result of waiting for observable QUIC connection activity.
public enum QUICActivityWaitResult: Sendable, Equatable {
    case activity
    case deadline
    case cancelled
}

public final class QUICEngineConnection<
    Environment: QUICRuntimeEnvironment
>: Sendable {
    // MARK: - State

    /// The value-type engine behind the facade lock. Every mutation is serialised
    /// here; the engine holds no lock of its own (caller-locked, sans-IO).
    private let engine: FacadeLock<QUICConnectionEngine>

    /// The UDP datagram seam this connection sends/receives on.
    private let transport: Environment.Transport

    /// The monotonic clock + sleep seam used to source `nowNanos` and to park the
    /// timer loop. The single timeline for the whole driver.
    private let timer: Environment.Timer

    /// The peer endpoint datagrams are sent to.
    private let peer: IPSocketEndpoint

    /// Facade-observable events, surfaced as the engine produces them. The
    /// public facade (or an Embedded consumer) drains these to wake stream reads,
    /// surface incoming streams, and observe handshake completion / close.
    private let events: FacadeLock<EventState>
    private let timerWakeups: FacadeLock<TimerWakeState>
    private let activityWaiters: FacadeLock<ActivityWaitState>
    private let runState: FacadeLock<Bool>

    private struct EventState: Sendable {
        var newStreams: [UInt64] = []
        var readableStreams: [UInt64] = []
        var datagrams: [[UInt8]] = []
        var handshakeData: [HandshakeChunk] = []
        var handshakeComplete: Bool = false
        var peerClosed: Bool = false
        var closeReason: ConnectionCloseSlot = .absent
        var lastReceiveError: QUICEngineError? = nil
    }

    private enum TimerWakeReason: Sendable {
        case signaled
        case terminated
    }

    private struct TimerWakeWaiter: Sendable {
        let token: UInt64
        let continuation: CheckedContinuation<TimerWakeReason, Never>
    }

    private struct TimerWakeState: Sendable {
        var pendingSignals: UInt64 = 0
        var waiter: TimerWakeWaiter? = nil
        var nextToken: UInt64 = 0
        var reservedTokens: Set<UInt64> = []
        var cancelledTokens: Set<UInt64> = []
        var terminated = false
    }

    private struct ActivityWaiter: Sendable {
        let token: UInt64
        let continuation: CheckedContinuation<Bool, Never>
    }

    private struct ActivityWaitState: Sendable {
        var generation: UInt64 = 0
        var nextToken: UInt64 = 0
        var reservedTokens: Set<UInt64> = []
        var cancelledTokens: Set<UInt64> = []
        var waiters: [ActivityWaiter] = []
        var terminated = false
    }

    private enum ActivityRaceOutcome: Sendable {
        case activity(Bool)
        case timerElapsed
        case timerFailed(TimeError)
    }

    private enum RunLoopOutcome: Sendable {
        case clean
        case cancelled
        case failed(QUICConnectionDriverError)
    }

    /// The last fatal receive error the engine surfaced (a per-packet decrypt
    /// failure is dropped, non-fatal, per RFC 9001 §5.5 and is NOT recorded here).
    /// `nil` until a fatal protocol error occurs.
    public var lastReceiveError: QUICEngineError? { events.withLock { $0.lastReceiveError } }

    // MARK: - Init

    /// Creates a driver from an already-initialised engine and the injected seams.
    ///
    /// The engine is created with `QUICConnectionEngine(configuration:nowNanos:)`
    /// by the caller (which fills the crypto/cert closures), so the cert/X.509
    /// strategy stays out of this driver.
    public init(
        engine: QUICConnectionEngine,
        transport: Environment.Transport,
        timer: Environment.Timer,
        peer: IPSocketEndpoint
    ) {
        self.engine = FacadeLock(engine)
        self.transport = transport
        self.timer = timer
        self.peer = peer
        self.events = FacadeLock(EventState())
        self.timerWakeups = FacadeLock(TimerWakeState())
        self.activityWaiters = FacadeLock(ActivityWaitState())
        self.runState = FacadeLock(false)
    }

    // MARK: - Run loop (I/O inversion + timer loop)

    /// Runs the connection: an inbound I/O loop and a timer loop, concurrently,
    /// until `receive()` reports clean shutdown or the connection closes.
    ///
    /// I/O inversion: `transport.receive()` → `engine.receive(...)` → send the
    /// engine's datagrams via `transport.send(...)`.
    /// Timer loop: park `timer.sleep(untilNanos:)` against the engine's earliest
    /// deadline; on wake `engine.handleTimeout(...)` and send its datagrams.
    public func run() async throws(QUICConnectionDriverError) {
        try await run(handshakeHandler: nil)
    }

    /// Runs the connection while delivering each complete TLS handshake message
    /// to the supplied session orchestrator. The handler executes after the QUIC
    /// engine lock is released. Any QUIC mutations it queues are flushed before
    /// the receive loop waits for the next datagram.
    public func run(
        handshakeHandler: @escaping QUICHandshakeHandler
    ) async throws(QUICConnectionDriverError) {
        try await run(handshakeHandler: Optional(handshakeHandler))
    }

    private func run(
        handshakeHandler: QUICHandshakeHandler?
    ) async throws(QUICConnectionDriverError) {
        let canStart = runState.withLock { started -> Bool in
            guard !started else { return false }
            started = true
            return true
        }
        guard canStart else {
            throw .engine(.invalidState("QUICEngineConnection.run() may be called only once"))
        }

        let failure = await withTaskGroup(
            of: RunLoopOutcome.self,
            returning: QUICConnectionDriverError?.self
        ) { group in
            group.addTask { await self.receiveLoop(handshakeHandler: handshakeHandler) }
            group.addTask { await self.timerLoop() }
            var firstFailure: QUICConnectionDriverError?
            var remaining = 2
            while remaining > 0, let outcome = await group.next() {
                remaining -= 1
                switch outcome {
                case .failed(let error):
                    if firstFailure == nil { firstFailure = error }
                    self.terminateTimerWakeups()
                    group.cancelAll()
                case .clean:
                    self.terminateTimerWakeups()
                    group.cancelAll()
                case .cancelled:
                    // Cancellation is not a terminal success. In particular, the
                    // timer waiter is cancelled when the receive loop reports a
                    // backend failure; wait for that sibling result so the failure
                    // cannot be raced into a clean completion.
                    break
                }
            }
            return firstFailure
        }
        terminateTimerWakeups()
        terminateActivityWaiters()
        if let failure {
            markConnectionClosed()
            throw failure
        }
        if Task.isCancelled {
            markConnectionClosed()
            throw .cancelled
        }
    }

    /// The inbound I/O loop: drains `transport.incoming`, feeds each datagram to
    /// the engine, and sends what the engine produces.
    private func receiveLoop(
        handshakeHandler: QUICHandshakeHandler?
    ) async -> RunLoopOutcome {
        while !Task.isCancelled && !isClosed {
            let datagram: InboundDatagram?
            do throws(DatagramError) {
                datagram = try await transport.receive()
            } catch let error {
                if error == .cancelled, Task.isCancelled {
                    return .cancelled
                }
                markConnectionClosed()
                return .failed(.transport(error))
            }
            guard let datagram else {
                markConnectionClosed()
                return .clean
            }

            let now: MonotonicInstant
            do throws(TimeError) {
                now = try timer.now()
            } catch let error {
                markConnectionClosed()
                return .failed(.time(error))
            }

            let output: QUICEngineOutput
            do throws(QUICEngineError) {
                output = try datagram.payload.withBorrowedBytes { payload throws(QUICEngineError) in
                    try self.receive(payload, nowNanos: now.nanoseconds)
                }
            } catch let error {
                markConnectionClosed()
                return .failed(.engine(error))
            }
            drain(output, includeHandshakeData: handshakeHandler == nil)

            if let handshakeHandler {
                var handshakeChunks = output.handshakeData
                var handshakeIndex = 0
                while handshakeIndex < handshakeChunks.count {
                    let chunk = handshakeChunks[handshakeIndex]
                    handshakeIndex += 1
                    do throws(QUICConnectionDriverError) {
                        try await handshakeHandler(chunk)
                    } catch let error {
                        markConnectionClosed()
                        return .failed(error)
                    }
                    // Installing keys may synchronously replay a packet that was
                    // received earlier and surface the next TLS message. Drain it
                    // into this same ordered handshake turn before flushing.
                    handshakeChunks.append(contentsOf: takeHandshakeData())
                }
            }

            var datagramsToSend = output.datagramsToSend
            if handshakeHandler != nil, !output.handshakeData.isEmpty {
                let handshakeDatagrams: [[UInt8]]
                do throws(QUICConnectionDriverError) {
                    handshakeDatagrams = try flushEngine(nowNanos: now.nanoseconds)
                } catch let error {
                    markConnectionClosed()
                    return .failed(error)
                }
                datagramsToSend.append(contentsOf: handshakeDatagrams)
            }

            signalTimer()
            do throws(DatagramError) {
                try await sendAll(datagramsToSend)
            } catch let error {
                markConnectionClosed()
                return .failed(.transport(error))
            }
        }
        if Task.isCancelled { return .cancelled }
        return .cancelled
    }

    /// The timer loop: parks against the engine's earliest deadline and drives
    /// `handleTimeout` on wake. No `ContinuousClock` / `Task.sleep` — the wait is
    /// the injected `AsyncTimer.sleep(untilNanos:)`.
    private func timerLoop() async -> RunLoopOutcome {
        while !Task.isCancelled {
            if isClosed { return .cancelled }
            let now: MonotonicInstant
            do throws(TimeError) {
                now = try timer.now()
            } catch let error {
                return .failed(.time(error))
            }
            let deadline = engine.withLock {
                $0.deadlines(nowNanos: now.nanoseconds).earliestDeadlineNanos
            }
            switch await waitForTimer(deadline: deadline, clockIdentifier: now.clockIdentifier) {
            case .signaled:
                continue
            case .cancelled:
                return .cancelled
            case .elapsed:
                break
            case .failed(let error):
                return .failed(.time(error))
            }

            let wakeNow: MonotonicInstant
            do throws(TimeError) {
                wakeNow = try timer.now()
            } catch let error {
                return .failed(.time(error))
            }
            let timeoutOutput: (datagrams: [[UInt8]], idleExpired: Bool)
            do throws(QUICEngineError) {
                timeoutOutput = try self.handleTimeout(nowNanos: wakeNow.nanoseconds)
            } catch let error {
                return .failed(.engine(error))
            }
            do throws(DatagramError) {
                try await sendAll(timeoutOutput.datagrams)
            } catch let error {
                return .failed(.transport(error))
            }
            if timeoutOutput.idleExpired {
                markConnectionClosed()
                return .clean
            }
        }
        return .cancelled
    }

    private enum TimerWaitOutcome: Sendable {
        case elapsed
        case signaled
        case cancelled
        case failed(TimeError)
    }

    private func waitForTimer(
        deadline: UInt64?,
        clockIdentifier: UInt64
    ) async -> TimerWaitOutcome {
        guard !Task.isCancelled else { return .cancelled }

        guard let deadline else {
            return await waitForTimerSignal() == .terminated ? .cancelled : .signaled
        }

        return await withTaskGroup(of: TimerWaitOutcome.self) { group in
            group.addTask {
                do throws(TimeError) {
                    try await self.timer.sleep(
                        until: MonotonicInstant(
                            clockIdentifier: clockIdentifier,
                            nanoseconds: deadline
                        )
                    )
                    return .elapsed
                } catch let error {
                    return error == .cancelled ? .cancelled : .failed(error)
                }
            }
            group.addTask {
                await self.waitForTimerSignal() == .terminated ? .cancelled : .signaled
            }

            let outcome = await group.next() ?? .cancelled
            group.cancelAll()
            await group.waitForAll()
            return outcome
        }
    }

    /// Transfers each produced datagram's array storage to the async transport
    /// owner without materializing another payload-sized buffer.
    private func sendAll(_ datagrams: [[UInt8]]) async throws(DatagramError) {
        for bytes in datagrams {
            try await transport.send(OwnedBytes(consuming: bytes), to: peer)
        }
    }

    // MARK: - Engine-driven I/O steps (under the lock)

    /// Feeds one inbound datagram to the engine, drains the engine's events into
    /// the facade event buffer, and returns the datagrams to send.
    private func receive(
        _ datagram: Span<UInt8>,
        nowNanos: UInt64
    ) throws(QUICEngineError) -> QUICEngineOutput {
        do throws(QUICEngineError) {
            return try engine.withLock { engine throws(QUICEngineError) in
                try engine.receive(datagram: datagram, nowNanos: nowNanos)
            }
        } catch let error {
            // A fatal protocol error closes the connection (the caller decides
            // policy via the surfaced close); a per-packet decrypt failure is
            // already dropped (non-fatal) inside the engine per RFC 9001 §5.5.
            events.withLock { $0.lastReceiveError = error }
            throw error
        }
    }

    /// Drives all elapsed timers, returning the datagrams to send and whether the
    /// idle timeout fired (terminal — the run loop tears down).
    private func handleTimeout(
        nowNanos: UInt64
    ) throws(QUICEngineError) -> (datagrams: [[UInt8]], idleExpired: Bool) {
        let output = try engine.withLock { engine throws(QUICEngineError) in
            try engine.handleTimeout(nowNanos: nowNanos)
        }
        return (output.datagramsToSend, output.idleExpired)
    }

    /// Copies an engine step's events into the facade event buffer.
    private func drain(
        _ output: QUICEngineOutput,
        includeHandshakeData: Bool = true
    ) {
        let hasActivity = !output.newStreams.isEmpty
            || !output.readableStreams.isEmpty
            || !output.datagrams.isEmpty
            || (includeHandshakeData && !output.handshakeData.isEmpty)
            || output.handshakeComplete
            || output.peerClosed
            || output.closeReason != nil
        events.withLock { e in
            e.newStreams.append(contentsOf: output.newStreams)
            e.readableStreams.append(contentsOf: output.readableStreams)
            e.datagrams.append(contentsOf: output.datagrams)
            if includeHandshakeData {
                e.handshakeData.append(contentsOf: output.handshakeData)
            }
            if output.handshakeComplete { e.handshakeComplete = true }
            if output.peerClosed { e.peerClosed = true }
            if case .present(let reason) = output.closeReasonSlot {
                e.closeReason = .present(reason)
            }
        }
        if hasActivity { signalActivity() }
    }

    // MARK: - Application API (engine ops under the lock)

    /// Whether the handshake is complete and application data flows.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// Whether the connection has been closed (locally or by the peer).
    public var isClosed: Bool { engine.withLock { $0.isClosed } }

    /// Monotonic generation for connection, handshake, and stream activity.
    /// Read this immediately before checking a condition, then pass the value to
    /// ``waitForActivity(after:until:)``. A signal racing the condition check is
    /// retained by the generation comparison rather than lost.
    public var activityGeneration: UInt64 {
        activityWaiters.withLock { $0.generation }
    }

    /// Publishes a higher-level state transition that becomes observable only
    /// after an asynchronous boundary, such as flushing the final TLS flight.
    /// The caller updates its state first so a woken waiter cannot observe the
    /// pre-transition value and miss completion.
    func notifyActivity() {
        signalActivity()
    }

    /// Suspends until activity occurs, the optional deadline elapses, or the
    /// connection/task terminates. Multiple stream readers may wait concurrently.
    public func waitForActivity(
        after observedGeneration: UInt64,
        until deadline: MonotonicInstant? = nil
    ) async throws(TimeError) -> QUICActivityWaitResult {
        guard let deadline else {
            return await waitForActivitySignal(after: observedGeneration)
                ? .activity
                : .cancelled
        }

        let outcome = await withTaskGroup(
            of: ActivityRaceOutcome.self,
            returning: ActivityRaceOutcome.self
        ) { group in
            group.addTask {
                .activity(await self.waitForActivitySignal(
                    after: observedGeneration
                ))
            }
            group.addTask {
                do throws(TimeError) {
                    try await self.timer.sleep(until: deadline)
                    return .timerElapsed
                } catch let error {
                    return .timerFailed(error)
                }
            }
            let first = await group.next() ?? .activity(false)
            group.cancelAll()
            await group.waitForAll()
            return first
        }
        switch outcome {
        case .activity(true):
            return .activity
        case .activity(false):
            return .cancelled
        case .timerElapsed:
            return .deadline
        case .timerFailed(let error):
            if error == .cancelled, Task.isCancelled {
                return .cancelled
            }
            throw error
        }
    }

    /// The current destination connection ID (post-migration aware).
    public var currentDestinationConnectionID: ConnectionID {
        engine.withLock { $0.currentDestinationConnectionID }
    }

    /// Opens a local stream and returns its ID.
    ///
    /// Opening a stream alone produces no wire bytes (a STREAM frame is only
    /// emitted once data is written), so this does NOT flush — the first
    /// ``writeStream(_:data:)`` (or ``finishStream(_:)``) sends the stream's bytes.
    public func openStream(bidirectional: Bool) throws(QUICEngineError) -> UInt64 {
        try run { (e) throws(QUICEngineError) in try e.openStream(bidirectional: bidirectional) }
    }

    /// Queues application bytes for a stream; the next flush frames and sends them.
    public func writeStream(
        _ id: UInt64,
        data: [UInt8]
    ) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.writeStream(id, data: data)
        }
        try await flushNow()
    }

    /// Drains contiguous received bytes from a stream's receive buffer.
    public func readStream(_ id: UInt64) -> [UInt8]? {
        engine.withLock { $0.readStream(id) }
    }

    /// Whether the stream's receive side has finished (FIN/RESET seen and all bytes
    /// drained), so a reader should observe clean end-of-stream at the stream level.
    public func streamReadFinished(_ id: UInt64) -> Bool {
        engine.withLock { $0.streamReadFinished(id) }
    }

    /// Marks a stream's send side finished (queues FIN) and flushes.
    public func finishStream(_ id: UInt64) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.finishStream(id)
        }
        try await flushNow()
    }

    /// Resets a stream's send side and flushes the RESET_STREAM frame.
    public func resetStream(
        _ id: UInt64,
        errorCode: UInt64
    ) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.resetStream(id, errorCode: errorCode)
        }
        try await flushNow()
    }

    /// Resets a stream after reliably delivering its prefix and flushes.
    public func resetStreamAt(
        _ id: UInt64,
        errorCode: UInt64,
        reliableSize: UInt64
    ) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.resetStreamAt(
                id,
                errorCode: errorCode,
                reliableSize: reliableSize
            )
        }
        try await flushNow()
    }

    /// Sends STOP_SENDING for a stream's receive side and flushes it.
    public func stopSending(
        _ id: UInt64,
        errorCode: UInt64
    ) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.stopSending(id, errorCode: errorCode)
        }
        try await flushNow()
    }

    /// Queues an unreliable DATAGRAM payload (RFC 9221) and flushes.
    public func sendDatagram(_ payload: [UInt8]) async throws(QUICConnectionDriverError) {
        try runForDriver { (engine) throws(QUICEngineError) in
            try engine.sendDatagram(payload)
        }
        try await flushNow()
    }

    /// Initiates a graceful close, sending a CONNECTION_CLOSE on the next flush.
    public func close(
        errorCode: UInt64,
        reason: [UInt8],
        isApplicationError: Bool
    ) async throws(QUICConnectionDriverError) {
        engine.withLock { $0.close(errorCode: errorCode, reason: reason, isApplicationError: isApplicationError) }
        try await flushNow()
    }

    /// Queues outbound CRYPTO bytes at an encryption level (the TLS seam produces
    /// these) and flushes. This is the handshake hand-off boundary.
    public func queueHandshake(
        _ data: [UInt8],
        level: EncryptionLevel
    ) async throws(QUICConnectionDriverError) {
        engine.withLock { $0.queueHandshake(data, level: level) }
        try await flushNow()
    }

    /// Installs handshake/application keys derived by the (async) TLS seam.
    public func installKeys(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) {
        let output = try run { (e) throws(QUICEngineError) in
            try e.installKeys(level: level, readSecret: readSecret, writeSecret: writeSecret, suite: suite)
        }
        drain(output)
    }

    /// Applies the peer's validated transport parameters.
    public func applyPeerTransportParameters(
        _ tp: TransportParametersCore
    ) throws(QUICEngineError) {
        try run { engine throws(QUICEngineError) in
            try engine.validateAndApplyPeerTransportParameters(tp)
        }
        signalTimer()
    }

    /// Marks the handshake complete (the TLS seam reports completion).
    public func markHandshakeComplete() async throws(QUICConnectionDriverError) {
        engine.withLock { $0.markHandshakeComplete() }
        try await flushNow()
    }

    /// Applies one ordered swift-tls output batch atomically to the QUIC engine.
    /// TLS-owned bytes and traffic secrets remain borrowed for the duration of
    /// this synchronous call. Handshake bytes are copied once into QUIC's send
    /// queue; application traffic secrets are copied once because QUIC must
    /// retain them for RFC 9001 key updates after the TLS output is destroyed.
    func applyTLSOutput(
        _ tlsOutput: consuming QUICTLSStepOutput
    ) throws(QUICConnectionDriverError) {
        var tlsOutput = consume tlsOutput
        var replayedOutputs: [QUICEngineOutput] = []
        try engine.withLock { engine throws(QUICConnectionDriverError) in
            do {
                while let effect = try tlsOutput.nextEffect() {
                    switch consume effect {
                    case .action(let action):
                        switch action {
                        case .emitHandshakeBytes(let level, let range):
                            try tlsOutput.withBorrowedBytes { bytes throws(QUICConnectionDriverError) in
                                guard range.endOffset <= bytes.count else {
                                    throw .engine(
                                        .invalidState("TLS output byte range exceeds its owner")
                                    )
                                }
                                engine.queueHandshake(
                                    bytes.extracting(range.offset..<range.endOffset),
                                    level: Self.encryptionLevel(level)
                                )
                            }
                        case .sendAlert(_, let alertCode):
                            engine.close(
                                errorCode: 0x100 + UInt64(alertCode),
                                reason: [],
                                isApplicationError: false
                            )
                        case .handshakeComplete:
                            engine.markHandshakeComplete()
                        case .handshakeConfirmed:
                            engine.markHandshakeConfirmed()
                        case .earlyDataAccepted, .earlyDataRejected:
                            break
                        }

                    case .trafficSecret(let event):
                        let secret = event.withBorrowedSecret { bytes in
                            Self.copyOwned(bytes)
                        }
                        let level: EncryptionLevel
                        switch event.level {
                        case .zeroRTT: level = .zeroRTT
                        case .handshake: level = .handshake
                        case .oneRTT: level = .application
                        }
                        let suite = try Self.protectionSuite(event.cipherSuite)
                        switch event.direction {
                        case .read:
                            replayedOutputs.append(try engine.installKeys(
                                level: level,
                                readSecret: secret,
                                writeSecret: nil,
                                suite: suite
                            ))
                        case .write:
                            replayedOutputs.append(try engine.installKeys(
                                level: level,
                                readSecret: nil,
                                writeSecret: secret,
                                suite: suite
                            ))
                        }
                    }
                }
            } catch let error as QUICTLSStepOutputError {
                throw .tls(.stepOutput(error))
            } catch let error as QUICConnectionDriverError {
                throw error
            } catch let error as QUICEngineError {
                throw .engine(error)
            } catch {
                throw .engine(.invalidState("unclassified TLS output failure"))
            }
        }
        for output in replayedOutputs where !output.isEmpty {
            drain(output)
        }
        signalTimer()
        signalActivity()
    }

    /// Initiates a 1-RTT key update (RFC 9001 §6.1), returning the new phase bit.
    public func performKeyUpdate() throws(QUICEngineError) -> UInt8 {
        try run { (e) throws(QUICEngineError) in try e.performKeyUpdate() }
    }

    // MARK: - Event draining (facade consumption)

    /// Drains complete TLS handshake messages the peer delivered, for the host
    /// TLS seam to consume one message at a time.
    public func takeHandshakeData() -> [HandshakeChunk] {
        events.withLock { e in
            let chunks = e.handshakeData
            e.handshakeData.removeAll()
            return chunks
        }
    }

    /// Drains and returns newly peer-opened stream IDs.
    public func takeNewStreams() -> [UInt64] {
        events.withLock { e in
            let s = e.newStreams
            e.newStreams.removeAll()
            return s
        }
    }

    /// Drains and returns stream IDs that became readable.
    public func takeReadableStreams() -> [UInt64] {
        events.withLock { e in
            let s = e.readableStreams
            e.readableStreams.removeAll()
            return s
        }
    }

    /// Drains and returns peer-delivered DATAGRAM payloads (RFC 9221).
    public func takeDatagrams() -> [[UInt8]] {
        events.withLock { e in
            let d = e.datagrams
            e.datagrams.removeAll()
            return d
        }
    }

    /// Whether the peer has closed the connection, and the reason if any.
    public var peerCloseReason: ConnectionCloseInfo? {
        events.withLock { $0.closeReason.value }
    }

    // MARK: - Private

    /// Assembles and sends whatever the engine now owes (after an application op).
    func flushNow() async throws(QUICConnectionDriverError) {
        let now: MonotonicInstant
        do throws(TimeError) {
            now = try timer.now()
        } catch let error {
            throw .time(error)
        }
        let datagrams = try flushEngine(nowNanos: now.nanoseconds)
        signalTimer()
        do throws(DatagramError) {
            try await sendAll(datagrams)
        } catch let error {
            throw .transport(error)
        }
    }

    private func flushEngine(
        nowNanos: UInt64
    ) throws(QUICConnectionDriverError) -> [[UInt8]] {
        do throws(QUICEngineError) {
            return try engine.withLock { engine throws(QUICEngineError) in
                try engine.flush(nowNanos: nowNanos)
            }
        } catch let error {
            throw .engine(error)
        }
    }

    private static func encryptionLevel(
        _ level: QUICHandshakeEncryptionLevel
    ) -> EncryptionLevel {
        switch level {
        case .initial: .initial
        case .handshake: .handshake
        case .oneRTT: .application
        }
    }

    private static func protectionSuite(
        _ suite: TLSCipherSuite
    ) throws(QUICConnectionDriverError) -> QUICProtectionSuite {
        switch suite {
        case .aes128GCM_SHA256: .aes128GCM
        case .aes256GCM_SHA384: .aes256GCM
        case .chacha20Poly1305_SHA256: .chaCha20Poly1305
        }
    }

    private static func copyOwned(_ bytes: Span<UInt8>) -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            result.append(bytes[index])
            index += 1
        }
        return result
    }

    private func waitForTimerSignal() async -> TimerWakeReason {
        let token = timerWakeups.withLock { state -> UInt64 in
            let token = state.nextToken
            state.nextToken &+= 1
            state.reservedTokens.insert(token)
            return token
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                registerTimerWaiter(token: token, continuation: continuation)
            }
        } onCancel: {
            cancelTimerWaiter(token: token)
        }
    }

    private func registerTimerWaiter(
        token: UInt64,
        continuation: CheckedContinuation<TimerWakeReason, Never>
    ) {
        let immediate = timerWakeups.withLock { state -> TimerWakeReason? in
            guard state.reservedTokens.remove(token) != nil else {
                return .terminated
            }
            if state.cancelledTokens.remove(token) != nil || state.terminated {
                return .terminated
            }
            if state.pendingSignals > 0 {
                state.pendingSignals -= 1
                return .signaled
            }
            state.waiter = TimerWakeWaiter(token: token, continuation: continuation)
            return nil
        }
        if let immediate { continuation.resume(returning: immediate) }
    }

    private func cancelTimerWaiter(token: UInt64) {
        let continuation = timerWakeups.withLock {
            state -> CheckedContinuation<TimerWakeReason, Never>? in
            if state.reservedTokens.contains(token) {
                state.cancelledTokens.insert(token)
                return nil
            }
            guard state.waiter?.token == token else { return nil }
            let continuation = state.waiter?.continuation
            state.waiter = nil
            return continuation
        }
        continuation?.resume(returning: .terminated)
    }

    private func signalTimer() {
        let waiter = timerWakeups.withLock { state -> CheckedContinuation<TimerWakeReason, Never>? in
            guard !state.terminated else { return nil }
            if let waiter = state.waiter {
                state.waiter = nil
                return waiter.continuation
            }
            state.pendingSignals &+= 1
            return nil
        }
        waiter?.resume(returning: .signaled)
    }

    private func terminateTimerWakeups() {
        let waiter = timerWakeups.withLock { state -> CheckedContinuation<TimerWakeReason, Never>? in
            state.terminated = true
            state.pendingSignals = 0
            state.reservedTokens.removeAll(keepingCapacity: false)
            state.cancelledTokens.removeAll(keepingCapacity: false)
            let waiter = state.waiter?.continuation
            state.waiter = nil
            return waiter
        }
        waiter?.resume(returning: .terminated)
    }

    private func waitForActivitySignal(
        after observedGeneration: UInt64
    ) async -> Bool {
        guard !Task.isCancelled else { return false }
        let token = activityWaiters.withLock { state -> UInt64 in
            let token = state.nextToken
            state.nextToken &+= 1
            state.reservedTokens.insert(token)
            return token
        }
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                registerActivityWaiter(
                    token: token,
                    after: observedGeneration,
                    continuation: continuation
                )
            }
        } onCancel: {
            cancelActivityWaiter(token: token)
        }
    }

    private func registerActivityWaiter(
        token: UInt64,
        after observedGeneration: UInt64,
        continuation: CheckedContinuation<Bool, Never>
    ) {
        let immediate = activityWaiters.withLock { state -> Bool? in
            guard state.reservedTokens.remove(token) != nil else {
                return false
            }
            if state.cancelledTokens.remove(token) != nil || state.terminated {
                return false
            }
            if state.generation != observedGeneration {
                return true
            }
            state.waiters.append(ActivityWaiter(
                token: token,
                continuation: continuation
            ))
            return nil
        }
        if let immediate { continuation.resume(returning: immediate) }
    }

    private func cancelActivityWaiter(token: UInt64) {
        let continuation = activityWaiters.withLock {
            state -> CheckedContinuation<Bool, Never>? in
            if state.reservedTokens.contains(token) {
                state.cancelledTokens.insert(token)
                return nil
            }
            guard let index = state.waiters.firstIndex(where: { $0.token == token }) else {
                return nil
            }
            return state.waiters.remove(at: index).continuation
        }
        continuation?.resume(returning: false)
    }

    private func signalActivity() {
        let continuations = activityWaiters.withLock {
            state -> [CheckedContinuation<Bool, Never>] in
            guard !state.terminated else { return [] }
            state.generation &+= 1
            var continuations: [CheckedContinuation<Bool, Never>] = []
            continuations.reserveCapacity(state.waiters.count)
            for waiter in state.waiters {
                continuations.append(waiter.continuation)
            }
            state.waiters.removeAll(keepingCapacity: true)
            return continuations
        }
        for continuation in continuations {
            continuation.resume(returning: true)
        }
    }

    private func terminateActivityWaiters() {
        let continuations = activityWaiters.withLock {
            state -> [CheckedContinuation<Bool, Never>] in
            guard !state.terminated else { return [] }
            state.terminated = true
            state.reservedTokens.removeAll(keepingCapacity: false)
            state.cancelledTokens.removeAll(keepingCapacity: false)
            var continuations: [CheckedContinuation<Bool, Never>] = []
            continuations.reserveCapacity(state.waiters.count)
            for waiter in state.waiters {
                continuations.append(waiter.continuation)
            }
            state.waiters.removeAll(keepingCapacity: false)
            return continuations
        }
        for continuation in continuations {
            continuation.resume(returning: false)
        }
    }

    private func markConnectionClosed() {
        engine.withLock { $0.markClosed() }
        terminateTimerWakeups()
        terminateActivityWaiters()
    }

    /// Runs an engine op under the lock, returning its typed result. The engine
    /// only throws `QUICEngineError`, so the closure is typed-throws (Embedded-clean
    /// — no `any Error` binding); the error is surfaced verbatim to the caller.
    private func run<R: Sendable>(
        _ body: (inout QUICConnectionEngine) throws(QUICEngineError) -> R
    ) throws(QUICEngineError) -> R {
        try engine.withLock { engine throws(QUICEngineError) in
            try body(&engine)
        }
    }

    private func runForDriver<R: Sendable>(
        _ body: (inout QUICConnectionEngine) throws(QUICEngineError) -> R
    ) throws(QUICConnectionDriverError) -> R {
        do throws(QUICEngineError) {
            return try run(body)
        } catch let error {
            throw .engine(error)
        }
    }
}
