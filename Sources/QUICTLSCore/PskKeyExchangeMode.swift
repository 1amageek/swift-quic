/// PSK key exchange modes (RFC 8446 §4.2.9).
///
/// Indicates which key establishment modes the client supports when offering
/// PSKs. TLS 1.3 over QUIC MUST use `psk_dhe_ke` (RFC 9001 §4.4). Pure value
/// data; Embedded-clean (no Foundation, no `any`).

public enum PskKeyExchangeMode: UInt8, Sendable, CaseIterable {
    /// PSK-only key establishment.
    /// No forward secrecy — compromise of the PSK reveals past sessions.
    case psk_ke = 0

    /// PSK with (EC)DHE key establishment.
    /// Provides forward secrecy via ephemeral DH.
    case psk_dhe_ke = 1
}
