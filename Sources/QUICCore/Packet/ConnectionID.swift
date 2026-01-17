/// QUIC Connection ID (RFC 9000 Section 5.1)
///
/// Connection IDs are used to identify connections at endpoints.
/// They can be 0-20 bytes in length.

import Foundation

/// A QUIC Connection ID
public struct ConnectionID: Hashable, Sendable {
    /// The raw bytes of the connection ID (0-20 bytes)
    public let bytes: Data

    /// Maximum length of a connection ID
    public static let maxLength = 20

    /// An empty connection ID (zero length)
    public static let empty = ConnectionID(bytes: Data())

    /// Creates a connection ID from raw bytes
    /// - Parameter bytes: The connection ID bytes (must be 0-20 bytes)
    /// - Precondition: bytes.count <= 20
    public init(bytes: Data) {
        precondition(bytes.count <= Self.maxLength, "Connection ID cannot exceed 20 bytes")
        self.bytes = bytes
    }

    /// Creates a connection ID from a byte sequence
    public init<S: Sequence>(_ bytes: S) where S.Element == UInt8 {
        self.init(bytes: Data(bytes))
    }

    /// The length of this connection ID in bytes
    public var length: Int {
        bytes.count
    }

    /// Whether this is an empty connection ID
    public var isEmpty: Bool {
        bytes.isEmpty
    }

    /// Generates a random connection ID of the specified length
    /// - Parameter length: The desired length (default: 8 bytes, must be 0-20)
    /// - Returns: A new random connection ID
    ///
    /// This implementation uses safe byte-level operations to avoid
    /// alignment issues and buffer overflows that can occur with
    /// `bindMemory(to: UInt64.self)` on unaligned or undersized buffers.
    public static func random(length: Int = 8) -> ConnectionID {
        precondition(length >= 0 && length <= maxLength)
        guard length > 0 else { return .empty }

        var bytes = Data(capacity: length)
        var generator = SystemRandomNumberGenerator()

        // Fill 8 bytes at a time using safe byte-level append
        var remaining = length
        while remaining >= 8 {
            var random = generator.next()
            withUnsafeBytes(of: &random) { buf in
                bytes.append(contentsOf: buf)
            }
            remaining -= 8
        }

        // Fill remaining bytes (0-7) safely
        if remaining > 0 {
            var random = generator.next()
            withUnsafeBytes(of: &random) { buf in
                bytes.append(contentsOf: buf.prefix(remaining))
            }
        }

        return ConnectionID(bytes: bytes)
    }
}

// MARK: - Encoding/Decoding

extension ConnectionID {
    /// Encodes the connection ID (length byte + data)
    public func encode() -> Data {
        var data = Data(capacity: 1 + bytes.count)
        data.append(UInt8(bytes.count))
        data.append(bytes)
        return data
    }

    /// Encodes the connection ID, appending to the given Data
    public func encode(to data: inout Data) {
        data.append(UInt8(bytes.count))
        data.append(bytes)
    }

    /// Encodes only the bytes (without length prefix)
    public func encodeBytes(to data: inout Data) {
        data.append(bytes)
    }

    /// Decodes a connection ID from data (reads length byte + data)
    /// - Parameter reader: The data reader
    /// - Returns: The decoded connection ID
    /// - Throws: Error if insufficient data
    public static func decode(from reader: inout DataReader) throws -> ConnectionID {
        guard let length = reader.readUInt8() else {
            throw DecodeError.insufficientData
        }
        guard length <= maxLength else {
            throw DecodeError.invalidLength(Int(length))
        }
        guard let bytes = reader.readBytes(Int(length)) else {
            throw DecodeError.insufficientData
        }
        return ConnectionID(bytes: bytes)
    }

    /// Decodes connection ID bytes (without length prefix) given a known length
    /// - Parameters:
    ///   - reader: The data reader
    ///   - length: The length of the connection ID
    /// - Returns: The decoded connection ID
    public static func decodeBytes(from reader: inout DataReader, length: Int) throws -> ConnectionID {
        guard length <= maxLength else {
            throw DecodeError.invalidLength(length)
        }
        guard length == 0 else {
            guard let bytes = reader.readBytes(length) else {
                throw DecodeError.insufficientData
            }
            return ConnectionID(bytes: bytes)
        }
        return .empty
    }

    /// Errors that can occur during decoding
    public enum DecodeError: Error, Sendable {
        case insufficientData
        case invalidLength(Int)
    }
}

// MARK: - CustomStringConvertible

extension ConnectionID: CustomStringConvertible {
    public var description: String {
        if bytes.isEmpty {
            return "ConnectionID(empty)"
        }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        return "ConnectionID(\(hex))"
    }
}

// MARK: - CustomDebugStringConvertible

extension ConnectionID: CustomDebugStringConvertible {
    public var debugDescription: String {
        description
    }
}
