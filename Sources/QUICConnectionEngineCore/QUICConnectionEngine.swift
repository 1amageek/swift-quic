// QUICConnectionEngine.swift
// The cored, Embedded-clean QUIC connection orchestrator (milestone M11).
//
// Mirrors the proven `DTLSClientEngine<C>` pattern from swift-tls:
//   * VALUE TYPE, CALLER-LOCKED — the engine holds NO lock; the host facade is
//     "the caller that locks" (it holds the engine behind a `FacadeLock`).
//   * SANS-IO — `receive(...)`/`send(...)`/`flush(...)` consume/produce bytes;
//     the facade performs the actual UDP I/O via its `DatagramTransport` seam.
//   * CLOCK-FREE — no `ContinuousClock`/`Task.sleep`/`Date`. Time enters ONLY as
//     an injected `nowNanos: UInt64`. `handleTimeout(nowNanos:)` is the
//     caller-driven retransmission/idle/ACK entrypoint (the QUIC analogue of
//     DTLS's `DTLSFlightController` + `handleTimeout()`); the engine reports the
//     next deadline set and the facade parks its `AsyncTimer` against it.
//   * NO `any` — generics over `C: CryptoProvider`; cipher-suite dispatch is the
//     closed `SuiteProtector<C>` enum; crypto/cert is injected via typed-throws
//     closures (X.509 never enters the engine).
//
// It DRIVES the existing cores (it does not reimplement them): the three
// packet-number spaces over `ConnectionStateCore` numbering, `LossDetectorCore`
// + `RTTEstimatorCore` + `CubicCore` + `PacerCore` + `AntiAmplificationCore`,
// `SendStreamCore`/`ReceiveStreamCore`/`FlowControllerCore`, `IdleTimeoutCore`,
// `PathValidationCore`, and `PacketParsingCore` over `SuiteProtector<C>`.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore
import P2PCoreCrypto

/// A value-type, caller-locked, sans-IO, clock-free QUIC connection engine.
///
/// `C` is the crypto provider seam; `T` is the monotonic clock the host facade
/// uses to source `nowNanos` (the engine never touches `T` — it is a phantom
/// parameter that documents the facade's clock dependency and keeps the public
/// type shape aligned with `Facade<C, T>`).
public struct QUICConnectionEngine<C: CryptoProvider, T: MonotonicClock>: Sendable {
    // MARK: - Immutable configuration

    let config: QUICConnectionEngineConfiguration<C>
    let isClient: Bool

    // MARK: - Connection identity & lifecycle

    /// The current destination CID (the peer's CID we send to). For a client
    /// this is updated to the server's SCID from the first server Initial.
    var destinationConnectionID: ConnectionID
    /// Our source CID (the peer's destination CID).
    var sourceConnectionID: ConnectionID
    /// The version in use.
    let version: QUICVersion

    /// High-level lifecycle status.
    var status: Status = .handshaking
    public enum Status: Sendable, Equatable {
        case handshaking
        case established
        case closing
        case closed
    }

    // MARK: - Keys / protection

    var keys: QUICKeyState<C>

    // MARK: - Packet-number spaces (RFC 9000 §12.3)

    var initialSpace = PacketNumberSpace()
    var handshakeSpace = PacketNumberSpace()
    var applicationSpace = PacketNumberSpace()

    // MARK: - Recovery (drives the cores)

    var rtt = RTTEstimatorCore()
    var congestion: CubicCore
    var pacer: PacerCore
    var antiAmplification: AntiAmplificationCore

    // MARK: - Streams

    var streams: QUICStreamSet

    // MARK: - Connection-level flow / handshake

    /// Reassembled, ordered CRYPTO data per level, ready to hand to the facade's
    /// TLS seam. Offsets enforced by per-level reassembly buffers.
    var cryptoReassembly: [EncryptionLevel: StreamReassemblyBuffer] = [:]
    /// Outbound CRYPTO send offset per level (for framing handshake bytes we send).
    var cryptoSendOffset: [EncryptionLevel: UInt64] = [:]
    /// Queued CRYPTO bytes awaiting framing per level.
    var cryptoSendQueue: [EncryptionLevel: [UInt8]] = [:]

    var handshakeConfirmed = false

    // MARK: - Timers

    var idleTimeout: IdleTimeoutCore
    var pathValidation: PathValidationCore
    var ptoCount: Int = 0

    // MARK: - Pending control frames

    /// Queued PATH_RESPONSE payloads to send (answers to peer PATH_CHALLENGE).
    var pendingPathResponses: [[UInt8]] = []
    /// Whether a HANDSHAKE_DONE frame is owed (server, after handshake complete).
    var handshakeDonePending = false
    /// Whether the peer sent HANDSHAKE_DONE (client confirms handshake).
    var pendingClose: ConnectionCloseInfo?
    /// Queued unreliable DATAGRAM payloads to send (RFC 9221).
    var pendingDatagrams: [[UInt8]] = []
    /// Peer's max DATAGRAM frame size (0 = datagrams not permitted by peer).
    var peerMaxDatagramFrameSize: UInt64 = 0
    /// Per-level pending PTO probe (PING) flags, set by the loss-detection timer.
    var pendingPing: [EncryptionLevel: Bool] = [:]
    /// Whether a local PATH_CHALLENGE is outstanding (arms the validation timer).
    var pathValidationPending = false

    // MARK: - Init

    /// Creates an engine from its configuration, deriving and installing Initial
    /// keys immediately (RFC 9001 §5.2). Throws if the version has no salt or the
    /// key derivation fails.
    public init(
        configuration: QUICConnectionEngineConfiguration<C>,
        nowNanos: UInt64
    ) throws(QUICEngineError) {
        self.config = configuration
        self.isClient = configuration.role == .client
        self.version = configuration.version
        self.sourceConnectionID = configuration.localConnectionID
        self.destinationConnectionID = configuration.initialPeerConnectionID

        let maxDatagram = configuration.maxDatagramSize
        self.congestion = CubicCore(maxDatagramSize: maxDatagram)
        // Start the pacer effectively unpaced until an RTT/cwnd is known.
        self.pacer = PacerCore(rate: UInt64.max, maxBurst: UInt64(maxDatagram) * 10, nowNanos: nowNanos)
        self.antiAmplification = AntiAmplificationCore(isServer: configuration.role == .server)

        let tp = configuration.localTransportParameters
        let fc = FlowControllerCore(
            isClient: configuration.role == .client,
            initialMaxData: tp.initialMaxData,
            initialMaxStreamDataBidiLocal: tp.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: tp.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: tp.initialMaxStreamDataUni,
            initialMaxStreamsBidi: tp.initialMaxStreamsBidi,
            initialMaxStreamsUni: tp.initialMaxStreamsUni,
            peerMaxData: 0,
            peerMaxStreamsBidi: 0,
            peerMaxStreamsUni: 0
        )
        self.streams = QUICStreamSet(
            isClient: configuration.role == .client,
            flowController: fc,
            initialMaxStreamDataBidiLocal: tp.initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: tp.initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: tp.initialMaxStreamDataUni,
            peerInitialMaxStreamDataBidiLocal: 0,
            peerInitialMaxStreamDataBidiRemote: 0,
            peerInitialMaxStreamDataUni: 0,
            maxBufferSize: 16 * 1024 * 1024
        )

        let idle = configuration.idleTimeoutNanos
        self.idleTimeout = IdleTimeoutCore(localTimeoutNanos: idle, nowNanos: nowNanos)
        self.pathValidation = PathValidationCore(validationTimeoutNanos: configuration.pathValidationTimeoutNanos)

        var keyState = QUICKeyState<C>()
        guard let salt = configuration.version.initialSaltBytes else {
            throw .transportParameter("unsupported QUIC version (no initial salt)")
        }
        try keyState.installInitial(
            connectionID: configuration.originalDestinationConnectionID.bytes,
            salt: salt,
            isClient: configuration.role == .client
        )
        self.keys = keyState
    }

    // MARK: - Public state accessors

    /// Whether the connection handshake is complete and application data flows.
    public var isEstablished: Bool { status == .established }

    /// Whether the connection has been closed (locally or by the peer).
    public var isClosed: Bool { status == .closed }

    /// The current 1-RTT key phase bit applied to outbound short-header packets.
    public var currentKeyPhase: UInt8 { keys.currentKeyPhase }

    /// The current destination connection ID (post-migration aware).
    public var currentDestinationConnectionID: ConnectionID { destinationConnectionID }

    // MARK: - Internal helpers (space access)
    func space(for level: EncryptionLevel) -> PacketNumberSpace {
        switch level {
        case .initial: return initialSpace
        case .handshake: return handshakeSpace
        case .zeroRTT, .application: return applicationSpace
        }
    }
    mutating func withSpace<R>(_ level: EncryptionLevel, _ body: (inout PacketNumberSpace) -> R) -> R {
        switch level {
        case .initial: return body(&initialSpace)
        case .handshake: return body(&handshakeSpace)
        case .zeroRTT, .application: return body(&applicationSpace)
        }
    }

    /// The encryption level a fresh STREAM/CRYPTO/control frame should use given
    /// the current key availability (1-RTT once application write keys exist).
    var currentSendLevel: EncryptionLevel {
        keys.hasWriteKeys(for: .application) ? .application : .initial
    }
}
