/// Named groups for (EC)DHE key exchange (RFC 8446 §4.2.7).
///
/// The wire-level code points for the supported_groups and key_share
/// extensions. Pure value data; Embedded-clean (no Foundation, no `any`).

public enum NamedGroup: UInt16, Sendable {
    case secp256r1 = 0x0017
    case secp384r1 = 0x0018
    case secp521r1 = 0x0019
    case x25519 = 0x001D
    case x448 = 0x001E
}
