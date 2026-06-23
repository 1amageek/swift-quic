/// TLS extension types (RFC 8446 §4.2).
///
/// The wire-level code points used by the handshake extensions QUIC's internal
/// TLS sends, including `quic_transport_parameters` (0x0039, RFC 9001 §8.2).
/// Pure value data; Embedded-clean (no Foundation, no `any`).

public enum TLSExtensionType: UInt16, Sendable {
    case serverName = 0                     // SNI
    case supportedGroups = 10               // Supported elliptic curves
    case signatureAlgorithms = 13           // Supported signature algorithms
    case alpn = 16                          // Application-Layer Protocol Negotiation
    case preSharedKey = 41                  // Pre-shared key
    case earlyData = 42                     // Early data (0-RTT)
    case supportedVersions = 43             // TLS versions supported
    case pskKeyExchangeModes = 45           // PSK key exchange modes
    case keyShare = 51                      // Key share for (EC)DHE
    case quicTransportParameters = 57       // QUIC transport parameters (0x0039)
}
