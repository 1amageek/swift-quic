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
//   * inverts I/O onto the `DatagramTransport` seam — it reads inbound datagrams
//     from `transport.incoming`, feeds them to `engine.receive(...)`, and sends
//     the engine's produced datagrams via `transport.send(...)`, and
//   * drives timers through the `AsyncTimer` seam — after each engine step it
//     reads `engine.deadlines(nowNanos:)`, parks `AsyncTimer.sleep(untilNanos:)`
//     against the earliest deadline, and on wake calls
//     `engine.handleTimeout(nowNanos:)` and sends its outputs.
//
// There is NO `ContinuousClock` / `Task.sleep` / `Date` here: the timeline comes
// from `Timer.monotonicNanos()` and the wait from `Timer.sleep(untilNanos:)`.
// Both seams are Embedded-clean (no `any`, no Foundation, no NIO), so this driver
// is dual-build: it compiles as an ordinary host type and under Embedded Swift.
//
// It is the canonical "rewired" path. The host public facade (`ManagedConnection`
// / `QUICEndpoint`) keeps its Foundation/NIO-typed surface (so swift-libp2p is
// unbroken) and is the host adapter over this driver.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICConnectionEngineCore
import P2PCoreCrypto
import P2PCoreTransport

/// A QUIC connection driven by the cored sans-IO engine over the
/// `DatagramTransport` + `AsyncTimer` seams.
///
/// `C` is the crypto provider seam, `Transport` the UDP datagram seam, and
/// `Timer` the monotonic-clock + sleep seam. The driver owns the run loop; the
/// embedder injects the transport + timer (host: NIO/POSIX transport +
/// `ContinuousClock`-backed timer; Embedded: a POSIX transport + a POSIX timer or
/// the embedder's own executor-backed `AsyncTimer`).
public final class QUICEngineConnection<
    C: CryptoProvider,
    Transport: DatagramTransport,
    Timer: AsyncTimer
>: Sendable {
    // MARK: - State

    /// The value-type engine behind the facade lock. Every mutation is serialised
    /// here; the engine holds no lock of its own (caller-locked, sans-IO).
    private let engine: FacadeLock<QUICConnectionEngine<C, Timer>>

    /// The UDP datagram seam this connection sends/receives on.
    private let transport: Transport

    /// The monotonic clock + sleep seam used to source `nowNanos` and to park the
    /// timer loop. The single timeline for the whole driver.
    private let timer: Timer

    /// The peer endpoint datagrams are sent to.
    private let peer: SocketEndpoint

    /// Facade-observable events, surfaced as the engine produces them. The
    /// host adapter (or an Embedded consumer) drains these to wake stream reads,
    /// surface incoming streams, and observe handshake completion / close.
    private let events: FacadeLock<EventState>

    private struct EventState: Sendable {
        var newStreams: [UInt64] = []
        var readableStreams: [UInt64] = []
        var datagrams: [[UInt8]] = []
        var handshakeData: [HandshakeChunk] = []
        var handshakeComplete: Bool = false
        var peerClosed: Bool = false
        var closeReason: ConnectionCloseInfo? = nil
        var lastReceiveError: QUICEngineError? = nil
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
        engine: QUICConnectionEngine<C, Timer>,
        transport: Transport,
        timer: Timer,
        peer: SocketEndpoint
    ) {
        self.engine = FacadeLock(engine)
        self.transport = transport
        self.timer = timer
        self.peer = peer
        self.events = FacadeLock(EventState())
    }

    // MARK: - Run loop (I/O inversion + timer loop)

    /// Runs the connection: an inbound I/O loop and a timer loop, concurrently,
    /// until the transport's `incoming` finishes or the connection closes.
    ///
    /// I/O inversion: `transport.incoming` → `engine.receive(...)` → send the
    /// engine's datagrams via `transport.send(...)`.
    /// Timer loop: park `timer.sleep(untilNanos:)` against the engine's earliest
    /// deadline; on wake `engine.handleTimeout(...)` and send its datagrams.
    public func run() async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.receiveLoop() }
            group.addTask { await self.timerLoop() }
            await group.waitForAll()
        }
    }

    /// The inbound I/O loop: drains `transport.incoming`, feeds each datagram to
    /// the engine, and sends what the engine produces.
    private func receiveLoop() async {
        do {
            for try await datagram in transport.incoming {
                let now = timer.monotonicNanos()
                let datagramsToSend = self.receive(datagram.payload, nowNanos: now)
                await sendAll(datagramsToSend)
                if isClosed { break }
            }
        } catch {
            // Transport iteration ended (closed / I/O failure). The connection
            // tears down; we do not silently retry.
        }
    }

    /// The timer loop: parks against the engine's earliest deadline and drives
    /// `handleTimeout` on wake. No `ContinuousClock` / `Task.sleep` — the wait is
    /// the injected `AsyncTimer.sleep(untilNanos:)`.
    private func timerLoop() async {
        while !isClosed {
            let now = timer.monotonicNanos()
            let deadline = engine.withLock { $0.deadlines(nowNanos: now).earliestDeadlineNanos }
            guard let deadline else {
                // No timer armed: park briefly and re-evaluate (a send on another
                // task can arm one). A small fixed quantum keeps this responsive
                // without a busy-loop; it is still seam-sourced, not ContinuousClock.
                do { try await timer.sleep(untilNanos: now &+ 50_000_000) }
                catch { return }
                continue
            }
            do { try await timer.sleep(untilNanos: deadline) }
            catch { return }   // cancelled

            let wakeNow = timer.monotonicNanos()
            let (datagrams, idleExpired) = self.handleTimeout(nowNanos: wakeNow)
            await sendAll(datagrams)
            if idleExpired { return }
        }
    }

    /// Sends each produced datagram via the transport seam (borrowed span; not
    /// retained past the call).
    private func sendAll(_ datagrams: [[UInt8]]) async {
        for bytes in datagrams {
            do {
                try await transport.send(bytes.span, to: peer)
            } catch {
                // A send failure is reported by the transport; we stop sending the
                // remaining datagrams in this batch rather than spinning.
                return
            }
        }
    }

    // MARK: - Engine-driven I/O steps (under the lock)

    /// Feeds one inbound datagram to the engine, drains the engine's events into
    /// the facade event buffer, and returns the datagrams to send.
    private func receive(_ datagram: [UInt8], nowNanos: UInt64) -> [[UInt8]] {
        let result: Result<QUICEngineOutput, QUICEngineError> = engine.withLock { engine in
            Result { () throws(QUICEngineError) -> QUICEngineOutput in
                try engine.receive(datagram: datagram, nowNanos: nowNanos)
            }
        }
        switch result {
        case .success(let output):
            drain(output)
            return output.datagramsToSend
        case .failure(let error):
            // A fatal protocol error closes the connection (the caller decides
            // policy via the surfaced close); a per-packet decrypt failure is
            // already dropped (non-fatal) inside the engine per RFC 9001 §5.5.
            events.withLock { $0.lastReceiveError = error }
            return []
        }
    }

    /// Drives all elapsed timers, returning the datagrams to send and whether the
    /// idle timeout fired (terminal — the run loop tears down).
    private func handleTimeout(nowNanos: UInt64) -> (datagrams: [[UInt8]], idleExpired: Bool) {
        let result: Result<QUICEngineTimerOutput, QUICEngineError> = engine.withLock { engine in
            Result { () throws(QUICEngineError) -> QUICEngineTimerOutput in
                try engine.handleTimeout(nowNanos: nowNanos)
            }
        }
        switch result {
        case .success(let output):
            return (output.datagramsToSend, output.idleExpired)
        case .failure:
            return ([], false)
        }
    }

    /// Copies an engine step's events into the facade event buffer.
    private func drain(_ output: QUICEngineOutput) {
        events.withLock { e in
            e.newStreams.append(contentsOf: output.newStreams)
            e.readableStreams.append(contentsOf: output.readableStreams)
            e.datagrams.append(contentsOf: output.datagrams)
            e.handshakeData.append(contentsOf: output.handshakeData)
            if output.handshakeComplete { e.handshakeComplete = true }
            if output.peerClosed { e.peerClosed = true }
            if let reason = output.closeReason { e.closeReason = reason }
        }
    }

    // MARK: - Application API (engine ops under the lock)

    /// Whether the handshake is complete and application data flows.
    public var isEstablished: Bool { engine.withLock { $0.isEstablished } }

    /// Whether the connection has been closed (locally or by the peer).
    public var isClosed: Bool { engine.withLock { $0.isClosed } }

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
    public func writeStream(_ id: UInt64, data: [UInt8]) async throws(QUICEngineError) {
        try run { (e) throws(QUICEngineError) in try e.writeStream(id, data: data) }
        await flushNow()
    }

    /// Drains contiguous received bytes from a stream's receive buffer.
    public func readStream(_ id: UInt64) -> [UInt8]? {
        engine.withLock { $0.readStream(id) }
    }

    /// Marks a stream's send side finished (queues FIN) and flushes.
    public func finishStream(_ id: UInt64) async throws(QUICEngineError) {
        try run { (e) throws(QUICEngineError) in try e.finishStream(id) }
        await flushNow()
    }

    /// Queues an unreliable DATAGRAM payload (RFC 9221) and flushes.
    public func sendDatagram(_ payload: [UInt8]) async throws(QUICEngineError) {
        try run { (e) throws(QUICEngineError) in try e.sendDatagram(payload) }
        await flushNow()
    }

    /// Initiates a graceful close, sending a CONNECTION_CLOSE on the next flush.
    public func close(errorCode: UInt64, reason: [UInt8], isApplicationError: Bool) async {
        engine.withLock { $0.close(errorCode: errorCode, reason: reason, isApplicationError: isApplicationError) }
        await flushNow()
    }

    /// Queues outbound CRYPTO bytes at an encryption level (the TLS seam produces
    /// these) and flushes. This is the handshake hand-off boundary.
    public func queueHandshake(_ data: [UInt8], level: EncryptionLevel) async {
        engine.withLock { $0.queueHandshake(data, level: level) }
        await flushNow()
    }

    /// Installs handshake/application keys derived by the (async) TLS seam.
    public func installKeys(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) {
        try run { (e) throws(QUICEngineError) in
            try e.installKeys(level: level, readSecret: readSecret, writeSecret: writeSecret, suite: suite)
        }
    }

    /// Applies the peer's validated transport parameters.
    public func applyPeerTransportParameters(_ tp: TransportParametersCore) {
        engine.withLock { $0.applyPeerTransportParameters(tp) }
    }

    /// Marks the handshake complete (the TLS seam reports completion).
    public func markHandshakeComplete() async {
        engine.withLock { $0.markHandshakeComplete() }
        await flushNow()
    }

    /// Initiates a 1-RTT key update (RFC 9001 §6.1), returning the new phase bit.
    public func performKeyUpdate() throws(QUICEngineError) -> UInt8 {
        try run { (e) throws(QUICEngineError) in try e.performKeyUpdate() }
    }

    // MARK: - Event draining (facade consumption)

    /// Drains and returns any handshake CRYPTO chunks the peer delivered, for the
    /// host TLS seam to consume.
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
        events.withLock { $0.closeReason }
    }

    // MARK: - Private

    /// Assembles and sends whatever the engine now owes (after an application op).
    private func flushNow() async {
        let now = timer.monotonicNanos()
        let result: Result<[[UInt8]], QUICEngineError> = engine.withLock { engine in
            Result { () throws(QUICEngineError) -> [[UInt8]] in try engine.flush(nowNanos: now) }
        }
        switch result {
        case .success(let datagrams):
            await sendAll(datagrams)
        case .failure:
            return
        }
    }

    /// Runs an engine op under the lock, returning its typed result. The engine
    /// only throws `QUICEngineError`, so the closure is typed-throws (Embedded-clean
    /// — no `any Error` binding); the error is surfaced verbatim to the caller.
    private func run<R: Sendable>(
        _ body: (inout QUICConnectionEngine<C, Timer>) throws(QUICEngineError) -> R
    ) throws(QUICEngineError) -> R {
        let result: Result<R, QUICEngineError> = engine.withLock { engine in
            Result { () throws(QUICEngineError) -> R in try body(&engine) }
        }
        switch result {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}
