/// Typed errors for the Embedded-clean TLS 1.3 client pre-ServerHello FSM
/// (``QUICClientHandshake``).
///
/// These are handshake-correctness errors for the ClientHello-production and
/// ServerHello/HelloRetryRequest-ingestion slice. Every failure is surfaced
/// explicitly to the caller (no silent fallback): an out-of-order message, a
/// downgrade-sentinel detection, a key-exchange failure, or a key-schedule
/// derivation failure fails the handshake closed. The adapter maps each case to
/// the corresponding TLS alert / `TLSHandshakeError` before converting it into a
/// QUIC CONNECTION_CLOSE frame.
///
/// Embedded-clean: no Foundation, no `any`. A closed enum; never silently swallowed.
import P2PCoreCrypto

/// Errors raised by the client pre-ServerHello handshake FSM.
public enum QUICClientHandshakeError: Error, Sendable, Equatable {
    /// A handshake message (or production request) arrived in a state where it is
    /// not permitted (e.g. a ServerHello before the ClientHello was produced, or a
    /// second HelloRetryRequest).
    case unexpectedMessage(QUICClientHandshakeStateTag)

    /// The ServerHello.random carried an RFC 8446 §4.1.3 downgrade sentinel — an
    /// attacker forced a TLS-version downgrade. Fail closed.
    case downgradeDetected

    /// The (EC)DHE key exchange failed (carries the seam error).
    case keyExchange(TLSKeyExchangeCoreError)

    /// The wire message failed to encode (carries the wire error).
    case wire(TLSWireError)

    /// A key-schedule derivation failed (e.g. an out-of-order transition or an
    /// HKDF bound violation).
    case keySchedule(TLSKeyScheduleError)

    /// An internal invariant was violated (e.g. a required secret was missing when
    /// handing off to the auth FSM).
    case internalInvariant(QUICClientHandshakeInvariantTag)
}

/// A compact, Embedded-clean tag identifying the FSM state an unexpected message
/// arrived in. Carries no Foundation/`String` payload so the error stays
/// Embedded-clean and `Equatable`.
public enum QUICClientHandshakeStateTag: Sendable, Equatable {
    case start
    case waitServerHello
    case waitServerHelloRetry
    case serverHelloProcessed
}

/// A compact tag naming an internal invariant violation in the pre-ServerHello FSM.
public enum QUICClientHandshakeInvariantTag: Sendable, Equatable {
    /// The auth machine was requested before ServerHello was processed (or a
    /// handshake secret was missing).
    case authMachineRequestedTooEarly
    /// The PSK binder build produced a ClientHello shorter than its binders section.
    case clientHelloShorterThanBinders
}
