/// TLS 1.3 Handshake Message Types (RFC 8446 Section 4)
///
/// All TLS handshake messages share a common header format:
/// ```
/// struct {
///     HandshakeType msg_type;    /* 1 byte */
///     uint24 length;             /* 3 bytes */
///     [message content]
/// } Handshake;
/// ```

import Foundation
@_exported import QUICTLSCore
// Re-export QUICCore so its `[UInt8] ⇄ Data` equality bridges (used to compare
// moved core `[UInt8]` byte fields against `Data` literals) are visible to
// `@testable import QUICCrypto` consumers without per-test `import QUICCore`.
@_exported import QUICCore

// `HandshakeType`, `CipherSuite`, `NamedGroup`, `SignatureScheme`, `TLSConstants`,
// and the TLS 1.3 handshake message/extension wire types now live in the
// Embedded-clean `QUICTLSCore` and are re-exported above so existing call sites
// and tests continue to see them as `QUICCrypto` symbols unchanged.

// MARK: - TLS Constants (Data view)

extension TLSConstants {
    /// HelloRetryRequest magic random value as `Data`.
    ///
    /// The core stores the sentinel as `[UInt8]`; this restores the historical
    /// `Data` surface for call sites that compare against `ServerHello.random`
    /// (whose `Data` view is provided by the message `Data`-compat shim).
    public static var helloRetryRequestRandomData: Data {
        Data(helloRetryRequestRandom)
    }
}

// MARK: - Handshake Codec

/// `Data`-based convenience surface for the handshake message framing.
///
/// The Embedded-clean core (``HandshakeMessageCodec`` in `QUICTLSCore`) does the
/// byte work on `[UInt8]`/`ByteReader`; this enum keeps the historical `Data`
/// API and maps the core's typed ``TLSWireError`` back to ``TLSDecodeError`` at
/// the boundary so existing call sites and tests are unchanged.
public enum HandshakeCodec {

    /// Encodes a handshake message with header
    /// - Parameters:
    ///   - type: The message type
    ///   - content: The message content (without header)
    /// - Returns: Complete message with 4-byte header
    public static func encode(type: HandshakeType, content: Data) -> Data {
        var data = Data(capacity: 4 + content.count)

        // HandshakeType (1 byte)
        data.append(type.rawValue)

        // Length (3 bytes, big-endian)
        let length = UInt32(content.count)
        data.append(UInt8((length >> 16) & 0xFF))
        data.append(UInt8((length >> 8) & 0xFF))
        data.append(UInt8(length & 0xFF))

        // Content
        data.append(content)

        return data
    }

    /// Decodes a handshake message header
    /// - Parameter data: Data containing at least 4 bytes
    /// - Returns: Tuple of (messageType, contentLength)
    public static func decodeHeader(from data: Data) throws -> (HandshakeType, Int) {
        do {
            return try HandshakeMessageCodec.decodeHeader(from: [UInt8](data))
        } catch {
            throw Self.mapWireError(error)
        }
    }

    /// Decodes a complete handshake message
    /// - Parameter data: Data containing header and content
    /// - Returns: Tuple of (messageType, content, totalBytesConsumed)
    public static func decodeMessage(from data: Data) throws -> (HandshakeType, Data, Int) {
        do {
            let result = try HandshakeMessageCodec.decodeMessage(from: [UInt8](data))
            return (result.type, Data(result.content), result.consumed)
        } catch {
            throw Self.mapWireError(error)
        }
    }

    /// Maps the core's typed ``TLSWireError`` back to the historical
    /// ``TLSDecodeError`` so callers and tests observe the same error surface.
    static func mapWireError(_ error: TLSWireError) -> TLSDecodeError {
        switch error {
        case .insufficientData(let expected, let actual):
            return .insufficientData(expected: expected, actual: actual)
        case .unknownHandshakeType(let byte):
            return .unknownHandshakeType(byte)
        case .invalidFormat(let reason):
            return .invalidFormat(reason)
        case .unsupportedVersion(let version):
            return .unsupportedVersion(version)
        case .handshakeDecodeError(let reason):
            // The header/message framing decoders never raise this (it is the
            // message-level CertificateRequest parser case); map it faithfully.
            return .invalidFormat(reason)
        case .bytes(let byteError):
            // The header/message decoders never raise `.bytes` (they use explicit
            // count guards, not a ByteReader), but map it faithfully rather than
            // fabricating a fallback so no information is silently dropped.
            return .invalidFormat("byte codec error: \(byteError)")
        }
    }
}

// MARK: - TLS Reader

/// Helper for reading TLS data structures
public struct TLSReader {
    private var data: Data
    private var offset: Int

    public init(data: Data) {
        self.data = data
        self.offset = data.startIndex
    }

    /// Remaining bytes to read
    public var remaining: Int {
        data.endIndex - offset
    }

    /// Whether there are more bytes to read
    public var hasMore: Bool {
        remaining > 0
    }

    /// Read a single byte
    public mutating func readUInt8() throws -> UInt8 {
        guard remaining >= 1 else {
            throw TLSDecodeError.insufficientData(expected: 1, actual: remaining)
        }
        let value = data[offset]
        offset += 1
        return value
    }

    /// Read a 16-bit big-endian integer
    public mutating func readUInt16() throws -> UInt16 {
        guard remaining >= 2 else {
            throw TLSDecodeError.insufficientData(expected: 2, actual: remaining)
        }
        let value = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
        offset += 2
        return value
    }

    /// Read a 24-bit big-endian integer
    public mutating func readUInt24() throws -> UInt32 {
        guard remaining >= 3 else {
            throw TLSDecodeError.insufficientData(expected: 3, actual: remaining)
        }
        let value = UInt32(data[offset]) << 16 |
                    UInt32(data[offset + 1]) << 8 |
                    UInt32(data[offset + 2])
        offset += 3
        return value
    }

    /// Read a 32-bit big-endian integer
    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else {
            throw TLSDecodeError.insufficientData(expected: 4, actual: remaining)
        }
        let value = UInt32(data[offset]) << 24 |
                    UInt32(data[offset + 1]) << 16 |
                    UInt32(data[offset + 2]) << 8 |
                    UInt32(data[offset + 3])
        offset += 4
        return value
    }

    /// Read exact number of bytes
    public mutating func readBytes(_ count: Int) throws -> Data {
        guard remaining >= count else {
            throw TLSDecodeError.insufficientData(expected: count, actual: remaining)
        }
        let bytes = data.subdata(in: offset..<(offset + count))
        offset += count
        return bytes
    }

    /// Read a variable-length vector with 1-byte length prefix
    public mutating func readVector8() throws -> Data {
        let length = Int(try readUInt8())
        return try readBytes(length)
    }

    /// Read a variable-length vector with 2-byte length prefix
    public mutating func readVector16() throws -> Data {
        let length = Int(try readUInt16())
        return try readBytes(length)
    }

    /// Read a variable-length vector with 3-byte length prefix
    public mutating func readVector24() throws -> Data {
        let length = Int(try readUInt24())
        return try readBytes(length)
    }

    /// Read all remaining bytes
    public mutating func readRemaining() -> Data {
        let bytes = data.subdata(in: offset..<data.endIndex)
        offset = data.endIndex
        return bytes
    }

    /// Create a sub-reader for a portion of data
    public mutating func subReader(length: Int) throws -> TLSReader {
        let subData = try readBytes(length)
        return TLSReader(data: subData)
    }
}

// MARK: - TLS Writer

/// Helper for writing TLS data structures
public struct TLSWriter {
    private var data: Data

    public init(capacity: Int = 256) {
        self.data = Data(capacity: capacity)
    }

    /// Get the written data
    public func finish() -> Data {
        data
    }

    /// Current size
    public var count: Int {
        data.count
    }

    /// Write a single byte
    public mutating func writeUInt8(_ value: UInt8) {
        data.append(value)
    }

    /// Write a 16-bit big-endian integer
    public mutating func writeUInt16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write a 24-bit big-endian integer
    public mutating func writeUInt24(_ value: UInt32) {
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write a 32-bit big-endian integer
    public mutating func writeUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    /// Write raw bytes
    public mutating func writeBytes(_ bytes: Data) {
        data.append(bytes)
    }

    /// Write a variable-length vector with 1-byte length prefix
    public mutating func writeVector8(_ bytes: Data) {
        writeUInt8(UInt8(bytes.count))
        writeBytes(bytes)
    }

    /// Write a variable-length vector with 2-byte length prefix
    public mutating func writeVector16(_ bytes: Data) {
        writeUInt16(UInt16(bytes.count))
        writeBytes(bytes)
    }

    /// Write a variable-length vector with 3-byte length prefix
    public mutating func writeVector24(_ bytes: Data) {
        writeUInt24(UInt32(bytes.count))
        writeBytes(bytes)
    }
}

// MARK: - Errors

/// Errors during TLS decoding
public enum TLSDecodeError: Error, Sendable {
    case insufficientData(expected: Int, actual: Int)
    case unknownHandshakeType(UInt8)
    case unknownExtensionType(UInt16)
    case invalidFormat(String)
    case unsupportedVersion(UInt16)
    case unexpectedMessage(expected: HandshakeType, received: HandshakeType)
}
