/// Unified typed error for the QUIC wire codec.
///
/// Embedded Swift requires typed throws end-to-end (no `any Error`). The wire
/// codec's primitives (`ByteReader`/`ByteWriter`) throw ``ByteError``; the codec
/// itself raises domain-specific failures (malformed varints, frames, headers,
/// out-of-range lengths). ``QUICWireError`` is the single closed enum that wraps
/// all of them so every codec entry point can declare `throws(QUICWireError)`
/// and callers get an exhaustive `catch`. There is no `try?` and no silent
/// fallback: every failure is a distinct typed case.

import P2PCoreBytes

public enum QUICWireError: Error, Equatable, Sendable {
    /// A lower-level byte read/write failed (insufficient bytes, overflow, ...).
    case bytes(ByteError)

    /// Not enough bytes remained to decode the requested structure.
    case insufficientData

    /// A QUIC variable-length integer was malformed or out of range.
    case invalidVarint

    /// An unsigned value exceeded the bound of its destination type / protocol limit.
    /// `context` names the field; `value`/`limit` describe the violation.
    case valueOutOfRange(context: String, value: UInt64, limit: UInt64)

    /// A frame type identifier was unknown or not permitted.
    case unknownFrameType(UInt64)

    /// A frame's structure violated its RFC 9000 encoding rules.
    case invalidFrameFormat(String)

    /// A packet header's structure violated its RFC 9000 encoding rules.
    case invalidPacketFormat(String)

    /// A Connection ID exceeded the 20-byte maximum (RFC 9000 §5.1) or a
    /// declared length was invalid.
    case invalidConnectionIDLength(Int)

    /// The packet header's fixed bit was not set (RFC 9000 §17).
    case fixedBitNotSet

    /// QUIC reserved header bits were not zero after header-protection removal.
    case reservedBitsNotZero(UInt8)

    /// A Retry packet was missing its 16-byte Retry Integrity Tag (RFC 9001 §5.8).
    case missingRetryIntegrityTag

    /// A NEW_CONNECTION_ID stateless reset token had the wrong length.
    case invalidStatelessResetTokenLength(actual: Int, expected: Int)

    /// NEW_CONNECTION_ID carried `retire_prior_to > sequence_number`
    /// (RFC 9000 §19.15 — FRAME_ENCODING_ERROR).
    case retirePriorToExceedsSequenceNumber(retirePriorTo: UInt64, sequenceNumber: UInt64)
}
