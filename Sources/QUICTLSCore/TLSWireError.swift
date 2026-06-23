/// Unified typed error for the TLS 1.3 handshake wire codec.
///
/// Embedded Swift requires typed throws end-to-end (no `any Error`). The wire
/// codec's primitives (`ByteReader`/`ByteWriter`) throw ``ByteError``; the
/// handshake codec itself raises domain-specific failures (truncated data,
/// unknown handshake types, malformed structures). ``TLSWireError`` is the single
/// closed enum that wraps all of them so every codec entry point can declare
/// `throws(TLSWireError)` and callers get an exhaustive `catch`. There is no
/// `try?` and no silent fallback: every failure is a distinct typed case.
///
/// The adapter (`QUICCrypto`) maps these back to its historical `TLSDecodeError`
/// at the `Data` boundary, so existing call sites and tests observe the same
/// error surface they always have.

import P2PCoreBytes

public enum TLSWireError: Error, Equatable, Sendable {
    /// A lower-level byte read/write failed (insufficient bytes, overflow, ...).
    case bytes(ByteError)

    /// Not enough bytes remained to decode the requested structure.
    /// `expected`/`actual` mirror the historical `TLSDecodeError.insufficientData`.
    case insufficientData(expected: Int, actual: Int)

    /// A handshake `msg_type` byte was not a known ``HandshakeType``.
    case unknownHandshakeType(UInt8)

    /// A structure violated its RFC 8446 encoding rules. `reason` names the field.
    case invalidFormat(String)
}
