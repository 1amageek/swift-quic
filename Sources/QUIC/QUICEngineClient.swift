// QUICEngineClient.swift
// The public, concrete `[UInt8]`-currency QUIC facade — the QUIC analogue of the
// proven swift-tls Tier-1 facade (`TLSClient`/`DTLSClient`, fixed to
// `TLSCryptoProvider`). It pins the crypto seam to `DefaultCryptoProvider` (host
// swift-crypto / Embedded BoringSSL) so a normal caller never spells the generic
// `C` parameter, and it carries currency `[UInt8]` / `SocketEndpoint` — never
// Foundation `Data` or NIO `SocketAddress`.
//
// DUAL-BUILD: this file is compiled in BOTH the host and Embedded builds of the
// `QUIC` target. On host it sits alongside the proven Foundation/NIO spine
// (`QUICEndpoint` / `ManagedConnection` / `QUICConnectionProtocol`), which is the
// path swift-libp2p uses and which stays UNCHANGED. Under Embedded the host spine
// is gated away (`#if !hasFeature(Embedded)`) and THIS facade — over the cored,
// sans-IO `QUICConnectionEngine` driver `QUICEngineConnection` — is the connection
// surface the QUIC target exposes.
//
// It is a thin pin over `QUICEngineConnection<C, Transport, Timer>`: it owns the
// engine construction (config + the host/Embedded crypto-cert capability strategy
// in `QUICEngineCapability`) and re-surfaces the engine driver's `[UInt8]`
// application/handshake/event API. The driver already holds the value-type engine
// behind a `FacadeLock` and inverts I/O onto the `DatagramTransport` + `AsyncTimer`
// seams, so this type adds no second lock — it forwards.
//
// PHASE-2 (DEFERRED, NOT this slice — documented, no silent fallback): Retry
// (RFC 9000 §8.1), 0-RTT (RFC 9001 §4.6), connection migration (RFC 9000 §9.3),
// and peer-initiated key-update live-wiring (RFC 9001 §6.2) are NOT wired on this
// Embedded path. The basic connection / stream / handshake / app-data path is
// fully supported via the engine; the deferred features surface as a typed throw
// (`QUICEngineError.invalidState`) rather than being silently mis-handled.

import _Concurrency   // REQUIRED under Embedded for async/Task
import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICConnectionEngineCore
import P2PCoreCrypto
import P2PCoreTransport
import P2PCrypto   // DefaultCryptoProvider (host swift-crypto / Embedded BoringSSL)

/// A QUIC connection with a concrete, Foundation-free `[UInt8]` surface.
///
/// `QUICEngineClient` is the public facade the QUIC target exposes under Embedded
/// (and a Foundation-free alternative on host): it pins the crypto provider to
/// ``DefaultCryptoProvider`` and forwards to the cored, sans-IO
/// ``QUICEngineConnection`` driver. The embedder injects the two platform seams it
/// cannot supply itself — the `Transport` (UDP datagram I/O) and the `Timer`
/// (monotonic clock + sleep) — so the same facade serves host and Embedded.
///
/// Currency is `[UInt8]` for stream / handshake bytes and ``SocketEndpoint`` for
/// peers. There is no Foundation `Data` or NIO `SocketAddress` on this surface.
public final class QUICEngineClient<
    Transport: DatagramTransport,
    Timer: AsyncTimer
>: Sendable {
    // MARK: - State

    /// The cored, sans-IO connection driver this facade pins to
    /// `DefaultCryptoProvider`. It already serialises every engine mutation behind
    /// a `FacadeLock` and owns the I/O inversion onto the seams, so this facade
    /// forwards rather than holding a second lock.
    private let connection: QUICEngineConnection<DefaultCryptoProvider, Transport, Timer>

    // MARK: - Init

    /// Wraps an already-built ``QUICEngineConnection`` driver pinned to
    /// ``DefaultCryptoProvider``.
    public init(
        connection: QUICEngineConnection<DefaultCryptoProvider, Transport, Timer>
    ) {
        self.connection = connection
    }

    /// Builds the connection from a configuration plus the injected seams, filling
    /// the engine's crypto/cert capability via ``QUICEngineCapability`` (host CSPRNG
    /// + X.509 validator, or Embedded RPK leaf-SPKI validator — both fail-closed).
    ///
    /// `peerValidator` is the caller's peer-trust decision over the raw DER chain
    /// (e.g. a libp2p PeerID match); `nil` means no chain is admitted on host and
    /// no identity is surfaced under Embedded (fail-closed, never a silent accept).
    ///
    /// - Throws: ``QUICEngineError`` if Initial-key derivation fails (e.g. an
    ///   unsupported QUIC version with no salt).
    public init(
        configuration: QUICConnectionEngineConfiguration<DefaultCryptoProvider>,
        transport: Transport,
        timer: Timer,
        peer: SocketEndpoint,
        peerValidator: QUICPeerValidator? = nil
    ) throws(QUICEngineError) {
        var config = configuration
        if config.randomBytes == nil {
            config.randomBytes = { count in QUICEngineCapability.randomBytes(count) }
        }
        if config.validateCertificate == nil {
            config.validateCertificate = QUICEngineCapability.validateCertificate(injected: peerValidator)
        }
        let engine = try QUICConnectionEngine<DefaultCryptoProvider, Timer>(
            configuration: config,
            nowNanos: timer.monotonicNanos()
        )
        self.connection = QUICEngineConnection(
            engine: engine,
            transport: transport,
            timer: timer,
            peer: peer
        )
    }

    // MARK: - Run loop

    /// Runs the connection's I/O + timer loops until the transport finishes or the
    /// connection closes. Forwards to the driver's run loop (I/O inversion +
    /// clock-free timer loop over the injected seams).
    public func run() async {
        await connection.run()
    }

    // MARK: - Connection state

    /// Whether the handshake is complete and application data flows.
    public var isEstablished: Bool { connection.isEstablished }

    /// Whether the connection has been closed (locally or by the peer).
    public var isClosed: Bool { connection.isClosed }

    /// The current destination connection ID (post-migration aware).
    public var currentDestinationConnectionID: ConnectionID {
        connection.currentDestinationConnectionID
    }

    /// The last fatal receive error the engine surfaced, or `nil`. A per-packet
    /// decrypt failure is dropped (non-fatal, RFC 9001 §5.5) and is NOT recorded.
    public var lastReceiveError: QUICEngineError? { connection.lastReceiveError }

    /// Whether the peer has closed the connection, and the reason if any.
    public var peerCloseReason: ConnectionCloseInfo? { connection.peerCloseReason }

    // MARK: - Streams (application data)

    /// Opens a local stream and returns its ID. Opening alone produces no wire
    /// bytes; the first ``writeStream(_:data:)`` / ``finishStream(_:)`` sends them.
    public func openStream(bidirectional: Bool) throws(QUICEngineError) -> UInt64 {
        try connection.openStream(bidirectional: bidirectional)
    }

    /// Queues `data` for `id` and flushes (frames + sends the stream bytes).
    public func writeStream(_ id: UInt64, data: [UInt8]) async throws(QUICEngineError) {
        try await connection.writeStream(id, data: data)
    }

    /// Drains contiguous received bytes from a stream's receive buffer, or `nil`.
    public func readStream(_ id: UInt64) -> [UInt8]? {
        connection.readStream(id)
    }

    /// Marks a stream's send side finished (queues FIN) and flushes.
    public func finishStream(_ id: UInt64) async throws(QUICEngineError) {
        try await connection.finishStream(id)
    }

    /// Queues an unreliable DATAGRAM payload (RFC 9221) and flushes.
    public func sendDatagram(_ payload: [UInt8]) async throws(QUICEngineError) {
        try await connection.sendDatagram(payload)
    }

    /// Initiates a graceful close, sending a CONNECTION_CLOSE on the next flush.
    public func close(errorCode: UInt64, reason: [UInt8], isApplicationError: Bool) async {
        await connection.close(errorCode: errorCode, reason: reason, isApplicationError: isApplicationError)
    }

    // MARK: - Handshake hand-off (the TLS seam boundary)

    /// Queues outbound CRYPTO bytes at an encryption level (the TLS seam produces
    /// these) and flushes. This is the handshake hand-off boundary.
    public func queueHandshake(_ data: [UInt8], level: EncryptionLevel) async {
        await connection.queueHandshake(data, level: level)
    }

    /// Installs handshake/application keys derived by the (async) TLS seam.
    public func installKeys(
        level: EncryptionLevel,
        readSecret: [UInt8]?,
        writeSecret: [UInt8]?,
        suite: QUICProtectionSuite
    ) throws(QUICEngineError) {
        try connection.installKeys(level: level, readSecret: readSecret, writeSecret: writeSecret, suite: suite)
    }

    /// Applies the peer's validated transport parameters (RFC 9000 §18.2).
    public func applyPeerTransportParameters(_ tp: TransportParametersCore) {
        connection.applyPeerTransportParameters(tp)
    }

    /// Marks the handshake complete (the TLS seam reports completion).
    public func markHandshakeComplete() async {
        await connection.markHandshakeComplete()
    }

    // MARK: - Event draining (facade consumption)

    /// Drains and returns the handshake CRYPTO chunks the peer delivered, for the
    /// TLS seam to consume.
    public func takeHandshakeData() -> [HandshakeChunk] {
        connection.takeHandshakeData()
    }

    /// Drains and returns newly peer-opened stream IDs.
    public func takeNewStreams() -> [UInt64] {
        connection.takeNewStreams()
    }

    /// Drains and returns stream IDs that became readable.
    public func takeReadableStreams() -> [UInt64] {
        connection.takeReadableStreams()
    }

    /// Drains and returns peer-delivered DATAGRAM payloads (RFC 9221).
    public func takeDatagrams() -> [[UInt8]] {
        connection.takeDatagrams()
    }

    // MARK: - 1-RTT key update (RFC 9001 §6.1, locally initiated)

    /// Initiates a LOCAL 1-RTT key update (RFC 9001 §6.1), returning the new phase
    /// bit. NOTE: PEER-initiated key-update live-wiring (detecting an inbound
    /// KEY_UPDATE and rotating in response, RFC 9001 §6.2) is Phase-2 deferred —
    /// the engine's `performKeyUpdate()` core exists but the inbound detection is
    /// not wired on this path (see ``requirePhase2Feature(_:)``).
    public func performKeyUpdate() throws(QUICEngineError) -> UInt8 {
        try connection.performKeyUpdate()
    }

    // MARK: - Phase-2 deferred features (explicit, no silent fallback)

    /// Reports a Phase-2 feature that this slice does NOT wire on the Embedded path.
    ///
    /// Retry / 0-RTT / connection-migration / peer-initiated key-update orchestration
    /// is deferred (quic Slice C Phase 2). Rather than silently mis-handling these,
    /// any call site that would need them throws here so the caller learns the
    /// feature is unavailable on this path (no silent fallback).
    public static func requirePhase2Feature(_ name: String) throws(QUICEngineError) -> Never {
        throw .invalidState("QUIC feature not wired on the engine facade path (Phase-2 deferred): \(name)")
    }
}
