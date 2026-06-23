/// TLS 1.3 handshake message types (RFC 8446 §4).
///
/// Every TLS handshake message begins with a one-byte `msg_type` followed by a
/// 24-bit length. This enum is the wire-level type tag; it is pure value data and
/// is Embedded-clean (no Foundation, no `any`).

public enum HandshakeType: UInt8, Sendable {
    case clientHello = 1
    case serverHello = 2
    case newSessionTicket = 4
    case endOfEarlyData = 5
    case encryptedExtensions = 8
    case certificate = 11
    case certificateRequest = 13
    case certificateVerify = 15
    case finished = 20
    case keyUpdate = 24
    case messageHash = 254
}
