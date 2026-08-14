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
//   * NO `any` — cipher-suite dispatch is the closed `SuiteProtector` enum.
//
// It DRIVES the existing cores (it does not reimplement them): three owned
// packet-number spaces, `LossDetectorCore`
// + `RTTEstimatorCore` + `CubicCore` + `PacerCore` + `AntiAmplificationCore`,
// `SendStreamCore`/`ReceiveStreamCore`/`FlowControllerCore`, `IdleTimeoutCore`,
// `PathValidationCore`, and `PacketParsingCore` over `SuiteProtector`.

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICRecoveryCore
import QUICStreamCore

/// A value-type, caller-locked, sans-IO, clock-free QUIC connection engine.
///
public struct QUICConnectionEngine: Sendable {
    // MARK: - Immutable configuration

    let config: QUICConnectionEngineConfiguration
    let isClient: Bool

    // MARK: - Connection identity & lifecycle

    /// The current destination CID (the peer's CID we send to). For a client
    /// this is updated to the server's SCID from the first server Initial.
    var destinationConnectionID: ConnectionID
    /// Our source CID (the peer's destination CID).
    var sourceConnectionID: ConnectionID
    /// The version in use.
    let version: QUICVersion
    /// Source CID from the first authenticated peer Initial. Later Initial
    /// packets with a different SCID are discarded (RFC 9000 section 7.2).
    var peerInitialSourceConnectionID: ConnectionID?
    /// Retry state retained through transport-parameter authentication.
    var retrySourceConnectionID: ConnectionID?
    var initialToken: [UInt8] = []
    var processedRetry = false
    var processedAuthenticatedPeerPacket = false
    /// Connection IDs issued by this endpoint and accepted as packet DCIDs.
    var localConnectionIDs: QUICConnectionIDState
    /// Connection IDs issued by the peer and eligible as packet destinations.
    var peerConnectionIDs: QUICConnectionIDState
    /// Limit the peer advertised for IDs that this endpoint may issue.
    var peerActiveConnectionIDLimit: UInt64 = 2

    /// High-level lifecycle status.
    var status: Status = .handshaking
    public enum Status: Sendable, Equatable {
        case handshaking
        case established
        case closing
        case closed
    }

    // MARK: - Keys / protection

    var keys: QUICKeyState

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

    /// Reassembled CRYPTO offsets per level. The companion message framers
    /// retain partial TLS headers/bodies and emit only complete messages.
    var cryptoReassembly = EncryptionLevelSlots<StreamReassemblyBuffer>()
    var cryptoMessageFraming = EncryptionLevelSlots<QUICCryptoMessageFramer>()
    /// Outbound CRYPTO send offset per level (for framing handshake bytes we send).
    var cryptoSendOffset = EncryptionLevelSlots<UInt64>()
    /// Queued CRYPTO bytes awaiting framing per level.
    var cryptoSendQueue = EncryptionLevelSlots<[UInt8]>()

    var handshakeConfirmed = false
    /// Absolute deadline for discarding the reordered-packet read generation.
    var previousReadKeysDiscardDeadlineNanos: UInt64?

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
    var pendingClose: ConnectionCloseSlot = .absent
    /// Queued unreliable DATAGRAM payloads to send (RFC 9221).
    var pendingDatagrams: [[UInt8]] = []
    /// Peer's max DATAGRAM frame size (0 = datagrams not permitted by peer).
    var peerMaxDatagramFrameSize: UInt64 = 0
    /// Whether the peer advertised RESET_STREAM_AT support.
    var peerEnableResetStreamAt = false
    /// Per-level pending PTO probe (PING) flags, set by the loss-detection timer.
    var pendingPing = EncryptionLevelSlots<Bool>()
    /// Frames collected from producer state but not yet successfully transmitted,
    /// plus retransmittable information restored after packet loss.
    var pendingFrames = EncryptionLevelSlots<[Frame]>()
    /// Retransmittable information retained until ACK or loss resolves its packet.
    var sentFrameLedger = EncryptionLevelSlots<UInt64ValueMap<[Frame]>>()
    /// Whether a local PATH_CHALLENGE is outstanding (arms the validation timer).
    var pathValidationPending = false
    /// ACK delay exponent this endpoint advertised and uses when encoding ACKs.
    let localAckDelayExponent: UInt64
    /// ACK delay exponent advertised by the peer and used when decoding ACKs.
    var peerAckDelayExponent: UInt64
    /// Peer-advertised max_ack_delay in nanoseconds, used by RTT/PTO logic.
    var peerMaxAckDelayNanos: UInt64

    // MARK: - Init

    /// Creates an engine from its configuration, deriving and installing Initial
    /// keys immediately (RFC 9001 §5.2). Throws if the version has no salt or the
    /// key derivation fails.
    public init(
        configuration: QUICConnectionEngineConfiguration,
        nowNanos: UInt64
    ) throws(QUICEngineError) {
        self.config = configuration
        self.isClient = configuration.role == .client
        self.version = configuration.version
        self.sourceConnectionID = configuration.localConnectionID
        self.destinationConnectionID = configuration.initialPeerConnectionID
        self.localConnectionIDs = QUICConnectionIDState(
            initialConnectionID: configuration.localConnectionID,
            statelessResetToken: configuration.localTransportParameters.statelessResetToken
        )
        self.peerConnectionIDs = QUICConnectionIDState(
            initialConnectionID: configuration.initialPeerConnectionID
        )

        let maxDatagram = configuration.maxDatagramSize
        self.congestion = CubicCore(maxDatagramSize: maxDatagram)
        // Start the pacer effectively unpaced until an RTT/cwnd is known.
        self.pacer = PacerCore(rate: UInt64.max, maxBurst: UInt64(maxDatagram) * 10, nowNanos: nowNanos)
        self.antiAmplification = AntiAmplificationCore(isServer: configuration.role == .server)

        let tp = configuration.localTransportParameters
        self.localAckDelayExponent = Self.boundedAckDelayExponent(tp.ackDelayExponent)
        self.peerAckDelayExponent = Self.defaultAckDelayExponent
        self.peerMaxAckDelayNanos = Self.defaultMaxAckDelayNanos
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

        var keyState = QUICKeyState()
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
    public var currentKeyPhase: UInt8 { keys.currentWriteKeyPhase }

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

    static var defaultAckDelayExponent: UInt64 { 3 }
    static var maxAckDelayExponent: UInt64 { 20 }
    static var defaultMaxAckDelayNanos: UInt64 { 25_000_000 }

    static func boundedAckDelayExponent(_ exponent: UInt64) -> UInt64 {
        min(exponent, maxAckDelayExponent)
    }

    static func millisecondsToNanos(_ milliseconds: UInt64) -> UInt64 {
        let (nanos, overflow) = milliseconds.multipliedReportingOverflow(by: 1_000_000)
        return overflow ? UInt64.max : nanos
    }

    static func ackDelayWireUnits(delayNanos: UInt64, exponent: UInt64) -> UInt64 {
        let delayMicros = delayNanos / 1_000
        return delayMicros >> boundedAckDelayExponent(exponent)
    }

    static func ackDelayNanos(wireUnits: UInt64, exponent: UInt64) -> UInt64 {
        let multiplier = UInt64(1) << boundedAckDelayExponent(exponent)
        let (micros, microsOverflow) = wireUnits.multipliedReportingOverflow(by: multiplier)
        if microsOverflow { return UInt64.max }
        let (nanos, nanosOverflow) = micros.multipliedReportingOverflow(by: 1_000)
        return nanosOverflow ? UInt64.max : nanos
    }
}
