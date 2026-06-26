/// QUIC Connection ID (RFC 9000 Section 5.1)
///
/// Connection IDs are used to identify connections at endpoints.
/// They can be 0-20 bytes in length.
///
/// Embedded-clean: no Foundation, no `any`. The raw bytes are `[UInt8]`; the
/// Foundation adapter restores the historical `Data` view / `Data` init.

import P2PCoreBytes

/// A QUIC Connection ID
public struct ConnectionID: Hashable, Sendable {
    /// The raw bytes of the connection ID (0-20 bytes)
    public let bytes: [UInt8]
    private let hashWord0: UInt64
    private let hashWord1: UInt64
    private let hashWord2: UInt64

    /// Maximum length of a connection ID
    public static let maxLength = 20

    /// An empty connection ID (zero length)
    public static let empty = ConnectionID(uncheckedBytes: [])

    /// Creates a connection ID from raw bytes with validation
    ///
    /// - Parameter bytes: The connection ID bytes (must be 0-20 bytes)
    /// - Throws: `ConnectionIDError.tooLong` if bytes exceed 20 bytes
    ///
    /// Use this initializer when creating a ConnectionID from untrusted input
    /// (e.g., network data, user input).
    public init(bytes: [UInt8]) throws(ConnectionIDError) {
        guard bytes.count <= Self.maxLength else {
            throw ConnectionIDError.tooLong(
                length: bytes.count,
                maxAllowed: Self.maxLength
            )
        }
        let hashWords = Self.packHashWords(bytes)
        self.bytes = bytes
        self.hashWord0 = hashWords.0
        self.hashWord1 = hashWords.1
        self.hashWord2 = hashWords.2
    }

    /// Creates a connection ID from raw bytes without validation
    ///
    /// - Parameter bytes: The connection ID bytes (must be 0-20 bytes)
    /// - Precondition: bytes.count <= maxLength (debug builds only)
    ///
    /// Use this initializer only when the bytes are known to be valid
    /// (e.g., locally generated, already validated).
    /// In debug builds, an assertion failure will occur if bytes exceed maxLength.
    /// In release builds, the ConnectionID will be created regardless.
    internal init(uncheckedBytes bytes: [UInt8]) {
        assert(bytes.count <= Self.maxLength,
               "ConnectionID unchecked init called with \(bytes.count) bytes (max: \(Self.maxLength))")
        let hashWords = Self.packHashWords(bytes)
        self.bytes = bytes
        self.hashWord0 = hashWords.0
        self.hashWord1 = hashWords.1
        self.hashWord2 = hashWords.2
    }

    /// Creates a connection ID from a byte sequence with validation
    ///
    /// - Throws: `ConnectionIDError.tooLong` if bytes exceed 20 bytes
    public init<S: Sequence>(_ bytes: S) throws(ConnectionIDError) where S.Element == UInt8 {
        try self.init(bytes: [UInt8](bytes))
    }

    /// Errors that can occur when creating a ConnectionID
    public enum ConnectionIDError: Error, Sendable, Equatable {
        /// The provided bytes exceed the maximum allowed length
        case tooLong(length: Int, maxAllowed: Int)
    }

    public static func == (lhs: ConnectionID, rhs: ConnectionID) -> Bool {
        lhs.bytes == rhs.bytes
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(hashWord0)
        hasher.combine(hashWord1)
        hasher.combine(hashWord2)
    }

    /// The length of this connection ID in bytes
    public var length: Int {
        bytes.count
    }

    /// Whether this is an empty connection ID
    public var isEmpty: Bool {
        bytes.isEmpty
    }

    private static func packHashWords(_ bytes: [UInt8]) -> (UInt64, UInt64, UInt64) {
        var word0: UInt64 = 0
        var word1: UInt64 = 0
        var word2: UInt64 = 0

        for (index, byte) in bytes.enumerated() {
            let shift = UInt64((index & 7) * 8)
            switch index >> 3 {
            case 0:
                word0 |= UInt64(byte) << shift
            case 1:
                word1 |= UInt64(byte) << shift
            default:
                word2 |= UInt64(byte) << shift
            }
        }

        word2 |= UInt64(bytes.count) << 56
        return (word0, word1, word2)
    }

    /// Generates a random connection ID of the specified length
    ///
    /// - Parameter length: The desired length (default: 8 bytes, must be 0-20)
    /// - Returns: A new random connection ID, or nil if length is invalid
    public static func random(length: Int = 8) -> ConnectionID? {
        guard length >= 0 && length <= maxLength else {
            return nil
        }
        guard length > 0 else { return .empty }

        var bytes: [UInt8] = []
        bytes.reserveCapacity(length)
        var generator = SystemRandomNumberGenerator()

        // Fill 8 bytes at a time using safe byte-level append
        var remaining = length
        while remaining >= 8 {
            let random = generator.next()
            var shift = 0
            while shift < 64 {
                bytes.append(UInt8((random >> UInt64(shift)) & 0xFF))
                shift += 8
            }
            remaining -= 8
        }

        // Fill remaining bytes (0-7) safely
        if remaining > 0 {
            let random = generator.next()
            var shift = 0
            var taken = 0
            while taken < remaining {
                bytes.append(UInt8((random >> UInt64(shift)) & 0xFF))
                shift += 8
                taken += 1
            }
        }

        // Length is validated above, so unchecked init is safe
        return ConnectionID(uncheckedBytes: bytes)
    }
}

// MARK: - Encoding/Decoding

extension ConnectionID {
    /// Encodes the connection ID (length byte + data) to a new byte array.
    public func encodeBytes() -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(1 + bytes.count)
        out.append(UInt8(bytes.count))
        out.append(contentsOf: bytes)
        return out
    }

    /// Encodes the connection ID (length byte + data), appending to the writer.
    public func encode(to writer: inout ByteWriter) {
        writer.writeByte(UInt8(bytes.count))
        writer.writeBytes(bytes)
    }

    /// Encodes only the bytes (without length prefix), appending to the writer.
    public func encodeBytes(to writer: inout ByteWriter) {
        writer.writeBytes(bytes)
    }

    /// Decodes a connection ID (reads length byte + data), advancing the reader.
    public static func decode(from reader: inout ByteReader) throws(DecodeError) -> ConnectionID {
        let length: UInt8
        do {
            length = try reader.readUInt8()
        } catch {
            throw DecodeError.insufficientData
        }
        guard length <= maxLength else {
            throw DecodeError.invalidLength(Int(length))
        }
        let bytes: [UInt8]
        do {
            bytes = try reader.readBytes(Int(length))
        } catch {
            throw DecodeError.insufficientData
        }
        // Length is validated above, so unchecked init is safe
        return ConnectionID(uncheckedBytes: bytes)
    }

    /// Decodes connection ID bytes (without length prefix) given a known length,
    /// advancing the reader.
    public static func decodeBytes(from reader: inout ByteReader, length: Int) throws(DecodeError) -> ConnectionID {
        guard length <= maxLength else {
            throw DecodeError.invalidLength(length)
        }
        guard length == 0 else {
            let bytes: [UInt8]
            do {
                bytes = try reader.readBytes(length)
            } catch {
                throw DecodeError.insufficientData
            }
            // Length is validated above, so unchecked init is safe
            return ConnectionID(uncheckedBytes: bytes)
        }
        return .empty
    }

    /// Errors that can occur during decoding
    public enum DecodeError: Error, Sendable, Equatable {
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
        return "ConnectionID(\(Self.hexString(bytes)))"
    }

    /// Lowercase hex of a byte array (Embedded-clean; no `String(format:)`).
    static func hexString(_ bytes: [UInt8]) -> String {
        let digits: [Character] = ["0", "1", "2", "3", "4", "5", "6", "7",
                                   "8", "9", "a", "b", "c", "d", "e", "f"]
        var chars: [Character] = []
        chars.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            chars.append(digits[Int(byte >> 4)])
            chars.append(digits[Int(byte & 0x0F)])
        }
        return String(chars)
    }
}

// MARK: - CustomDebugStringConvertible

extension ConnectionID: CustomDebugStringConvertible {
    public var debugDescription: String {
        description
    }
}
