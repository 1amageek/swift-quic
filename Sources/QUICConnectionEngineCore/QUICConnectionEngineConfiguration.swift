// QUICConnectionEngineConfiguration.swift
// The injection surface for `QUICConnectionEngine<C, T>`: negotiation knobs plus
// the typed-throws closures that supply crypto/cert capability the engine must
// not own. Mirrors `DTLSEngineConfiguration<C>` — X.509 stays OUT of the engine;
// CertificateVerify possession is checked in-core, trust is delegated fail-closed.

import QUICWire
import QUICConnectionCore
import P2PCoreCrypto

/// Engine role.
public enum QUICEngineRole: Sendable, Equatable {
    case client
    case server
}

/// Configuration + injected capability for a ``QUICConnectionEngine``.
///
/// `C` is the crypto provider seam (key derivation / AEAD / header protection).
/// Everything that requires Foundation, X.509, or an async runtime is supplied as
/// a `@Sendable` typed-throws closure, so the engine stays a pure value type that
/// compiles under Embedded Swift.
public struct QUICConnectionEngineConfiguration<C: CryptoProvider>: Sendable {
    // MARK: - Identity & negotiation

    /// Whether this endpoint is the client or the server.
    public var role: QUICEngineRole

    /// The QUIC version (default v1, RFC 9000).
    public var version: QUICVersion

    /// The local connection ID (the peer's destination CID for packets to us).
    public var localConnectionID: ConnectionID

    /// The initial peer connection ID (our destination CID). For a client, this
    /// is the random DCID used to derive Initial keys; for a server it is the
    /// client's source CID.
    public var initialPeerConnectionID: ConnectionID

    /// The original destination CID used to derive Initial secrets (RFC 9001
    /// §5.2). For a client this equals ``initialPeerConnectionID``; for a server
    /// it is the DCID from the client's first Initial.
    public var originalDestinationConnectionID: ConnectionID

    /// Local transport parameters (already-validated value type, RFC 9000 §18).
    public var localTransportParameters: TransportParametersCore

    /// The largest UDP payload the path will accept (anti-amplification + MTU).
    public var maxDatagramSize: Int

    // MARK: - Timer tuning (all nanoseconds; clock-free)

    /// Local idle timeout in nanoseconds (RFC 9000 §10.1). `0` disables it.
    public var idleTimeoutNanos: UInt64

    /// Maximum ACK delay this endpoint will introduce, in nanoseconds
    /// (RFC 9000 §18.2 `max_ack_delay`, default 25 ms).
    public var maxAckDelayNanos: UInt64

    /// Path-validation timeout in nanoseconds (RFC 9000 §8.2.4).
    public var pathValidationTimeoutNanos: UInt64

    // MARK: - Injected crypto/cert capability (X.509 stays out of the engine)

    /// Supplies `count` cryptographically-random bytes (CIDs, PATH_CHALLENGE
    /// data, etc.). Injected because a CSPRNG is a host capability.
    public var randomBytes: (@Sendable (_ count: Int) -> [UInt8])?

    /// Validates the peer certificate chain AFTER the in-core CertificateVerify
    /// possession check. FAIL-CLOSED: a throw aborts the connection. Returns an
    /// optional opaque peer identifier (e.g. a libp2p PeerID). Only the DER bytes
    /// cross the boundary — no X.509 types enter the engine.
    public var validateCertificate: (@Sendable (_ certificateChainDER: [[UInt8]]) throws(QUICEngineError) -> [UInt8]?)?

    public init(
        role: QUICEngineRole,
        version: QUICVersion = .v1,
        localConnectionID: ConnectionID,
        initialPeerConnectionID: ConnectionID,
        originalDestinationConnectionID: ConnectionID,
        localTransportParameters: TransportParametersCore,
        maxDatagramSize: Int = 1200,
        idleTimeoutNanos: UInt64 = 30_000_000_000,
        maxAckDelayNanos: UInt64 = 25_000_000,
        pathValidationTimeoutNanos: UInt64 = 3_000_000_000,
        randomBytes: (@Sendable (_ count: Int) -> [UInt8])? = nil,
        validateCertificate: (@Sendable (_ certificateChainDER: [[UInt8]]) throws(QUICEngineError) -> [UInt8]?)? = nil
    ) {
        self.role = role
        self.version = version
        self.localConnectionID = localConnectionID
        self.initialPeerConnectionID = initialPeerConnectionID
        self.originalDestinationConnectionID = originalDestinationConnectionID
        self.localTransportParameters = localTransportParameters
        self.maxDatagramSize = maxDatagramSize
        self.idleTimeoutNanos = idleTimeoutNanos
        self.maxAckDelayNanos = maxAckDelayNanos
        self.pathValidationTimeoutNanos = pathValidationTimeoutNanos
        self.randomBytes = randomBytes
        self.validateCertificate = validateCertificate
    }
}
