// QUICEngineError.swift
// The single typed error the value-type, sans-IO `QUICConnectionEngine` throws.
//
// Embedded-clean: no Foundation, no `any`. Every fallible engine entrypoint is
// `throws(QUICEngineError)`, so the host facade can map it to its public error
// inside the lock (mirroring the proven `DTLSEngineError` → `TLSError` pattern).
// Decrypt / cert / transport-parameter failures surface as a typed throw — never
// a silent fallback (the caller decides how to react).

import QUICWire
import QUICPacketProtectionCore
import QUICConnectionCore
import QUICStreamCore

/// The typed error surface of ``QUICConnectionEngine``.
///
/// The engine never performs I/O and never silently degrades: a failure to
/// decrypt a packet, an invalid frame, a flow-control / final-size violation,
/// or an exhausted packet-number space is reported here and the caller (the host
/// facade) decides whether to close the connection. The associated payloads keep
/// the originating core error so a precise reason survives the boundary.
public enum QUICEngineError: Error, Sendable {
    /// The engine was driven in a state where the operation is invalid
    /// (e.g. `send` before the handshake produced application keys).
    case invalidState(String)

    /// A required configuration seam (crypto / cert closure, transport params)
    /// was absent. The engine refuses to proceed rather than guess.
    case missingConfiguration(String)

    /// Packet parsing / decryption failed (RFC 9000 §12 / RFC 9001 §5).
    case packetParsing(PacketParsingError)

    /// Packet serialization / protection failed.
    case packetProtection(PacketProtectionError)

    /// A frame violated a protocol invariant (final-size, flow-control,
    /// stream-limit, etc.). Carries the originating stream-core error.
    case stream(StreamError)

    /// A flow-control or connection-level limit was exceeded.
    case flowControl(String)

    /// A packet-number space ran out of usable numbers (2^62, RFC 9000 §12.3):
    /// the connection MUST be closed rather than wrapping.
    case packetNumberExhausted(EncryptionLevel)

    /// The cryptographic keys for the requested encryption level are not
    /// installed (no silent drop — the caller learns the level is unkeyed).
    case keysUnavailable(EncryptionLevel)

    /// A crypto / certificate closure injected via the configuration threw.
    /// Carries a human-readable reason (the closure's own typed error is folded
    /// into a string so X.509 types never cross into the engine).
    case cryptoClosureFailed(String)

    /// The connection has been closed (locally or by the peer); the operation is
    /// no longer permitted.
    case connectionClosed

    /// A transport-parameter value was malformed or violated RFC 9000 §18.2
    /// (e.g. an `initial_source_connection_id` mismatch).
    case transportParameter(String)

    /// The datagram was too large for the negotiated / discovered path MTU.
    case datagramTooLarge(size: Int, maximum: Int)
}
