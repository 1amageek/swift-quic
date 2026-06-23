/// Encoder/decoder for the TLS 1.3 handshake message framing (RFC 8446 §4).
///
/// Every TLS handshake message shares a common 4-byte header:
/// ```
/// struct {
///     HandshakeType msg_type;    /* 1 byte */
///     uint24 length;             /* 3 bytes */
///     [message content]
/// } Handshake;
/// ```
///
/// This is the Embedded-clean core of the framing codec: it operates on
/// `[UInt8]` and the `P2PCoreBytes` `ByteReader`/`ByteWriter`, throws the closed
/// ``TLSWireError`` (no `any Error`), and has no Foundation/`Mutex`/
/// `ContinuousClock` dependency. The `QUICCrypto` adapter's `HandshakeCodec`
/// delegates its historical `Data` API to this type.
///
/// Typed-throws note: `ByteReader`/`ByteWriter` throw ``ByteError``; we unwrap
/// them at the boundary with a bare `do/catch { switch }` (the proven recipe;
/// the SILGen-crashing generic typed-throws helper is avoided).

import P2PCoreBytes

public enum HandshakeMessageCodec {

    /// The fixed handshake header length in bytes (msg_type + uint24 length).
    public static let headerLength = 4

    /// The maximum content length encodable in the 24-bit length field.
    public static let maxContentLength = 0xFF_FFFF

    // MARK: - Encoding

    /// Encodes a handshake message: a 4-byte header followed by `content`.
    ///
    /// - Parameters:
    ///   - type: The message type tag written to the first byte.
    ///   - content: The message body (without header).
    /// - Returns: The complete message bytes.
    /// - Throws: ``TLSWireError/invalidFormat(_:)`` if `content` exceeds the
    ///   24-bit length field.
    public static func encode(
        type: HandshakeType,
        content: [UInt8]
    ) throws(TLSWireError) -> [UInt8] {
        guard content.count <= maxContentLength else {
            throw TLSWireError.invalidFormat("Handshake content too long: \(content.count)")
        }
        var writer = ByteWriter(reservingCapacity: headerLength + content.count)
        writer.writeUInt8(type.rawValue)
        let length = UInt32(content.count)
        do {
            try writer.writeUInt24(length)
        } catch {
            // writeUInt24 only fails on > 0xFFFFFF, which we guarded above.
            switch error {
            case .lengthOutOfRange:
                throw TLSWireError.invalidFormat("Handshake content too long: \(content.count)")
            default:
                throw TLSWireError.bytes(error)
            }
        }
        writer.writeBytes(content)
        return writer.finishArray()
    }

    // MARK: - Decoding

    /// Decodes a handshake message header from the start of `bytes`.
    ///
    /// - Returns: The message type and its declared content length.
    /// - Throws: ``TLSWireError/insufficientData(expected:actual:)`` if fewer
    ///   than 4 bytes are present, or ``TLSWireError/unknownHandshakeType(_:)``.
    public static func decodeHeader(
        from bytes: [UInt8]
    ) throws(TLSWireError) -> (type: HandshakeType, length: Int) {
        guard bytes.count >= headerLength else {
            throw TLSWireError.insufficientData(expected: headerLength, actual: bytes.count)
        }
        guard let type = HandshakeType(rawValue: bytes[0]) else {
            throw TLSWireError.unknownHandshakeType(bytes[0])
        }
        let length = Int(bytes[1]) << 16 | Int(bytes[2]) << 8 | Int(bytes[3])
        return (type, length)
    }

    /// Decodes a complete handshake message from the start of `bytes`.
    ///
    /// - Returns: The message type, its content (a copy, without header), and the
    ///   total number of bytes consumed (header + content).
    /// - Throws: ``TLSWireError/insufficientData(expected:actual:)`` if the
    ///   declared message extends past `bytes`.
    public static func decodeMessage(
        from bytes: [UInt8]
    ) throws(TLSWireError) -> (type: HandshakeType, content: [UInt8], consumed: Int) {
        let header = try decodeHeader(from: bytes)
        let total = headerLength + header.length
        guard bytes.count >= total else {
            throw TLSWireError.insufficientData(expected: total, actual: bytes.count)
        }
        let content = Array(bytes[headerLength..<total])
        return (header.type, content, total)
    }
}
