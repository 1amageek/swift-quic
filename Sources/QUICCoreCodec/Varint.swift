/// QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
///
/// QUIC uses a variable-length integer encoding that can represent values
/// from 0 to 2^62-1. The encoding uses the two most significant bits to
/// indicate the length of the integer:
///
/// ```
/// 2MSB = 00: 6-bit value  (1 byte,  max 63)
/// 2MSB = 01: 14-bit value (2 bytes, max 16383)
/// 2MSB = 10: 30-bit value (4 bytes, max 1073741823)
/// 2MSB = 11: 62-bit value (8 bytes, max 4611686018427387903)
/// ```
///
/// Embedded-clean: no Foundation, no `any`. The byte container is `[UInt8]`;
/// reading/writing flows through `P2PCoreBytes` `ByteReader`/`ByteWriter`.

import P2PCoreBytes

/// QUIC variable-length integer
public struct Varint: Hashable, Sendable {
    /// The decoded value
    public let value: UInt64

    /// Maximum value representable by a QUIC varint (2^62 - 1)
    public static let maxValue: UInt64 = (1 << 62) - 1

    /// Creates a Varint from a UInt64 value
    /// - Parameter value: The value (must be <= 2^62 - 1)
    /// - Precondition: value must be representable in 62 bits
    public init(_ value: UInt64) {
        precondition(value <= Self.maxValue, "Varint value exceeds maximum (2^62 - 1)")
        self.value = value
    }

    /// Creates a Varint from any BinaryInteger
    public init<T: BinaryInteger>(_ value: T) {
        self.init(UInt64(value))
    }

    /// The minimum number of bytes needed to encode this value
    public var encodedLength: Int {
        Self.encodedLength(for: value)
    }
}

// MARK: - Encoding

extension Varint {
    /// Encodes the varint to a new byte array.
    public func encodeBytes() -> [UInt8] {
        var writer = ByteWriter(reservingCapacity: encodedLength)
        // A Varint is constructed only with values <= maxValue, so the QUIC
        // varint write cannot overflow. The init precondition guarantees this.
        do {
            try writer.writeVarint(value)
        } catch {
            // Unreachable for a valid Varint (value <= 2^62 - 1, enforced at init).
            fatalError("Varint encode exceeded the QUIC varint range: \(value)")
        }
        return writer.finishArray()
    }

    /// Encodes the varint, appending to the given writer.
    public func encode(to writer: inout ByteWriter) throws(QUICWireError) {
        try writer.qWriteVarint(value)
    }
}

// MARK: - Decoding

extension Varint {
    /// Error thrown when decoding fails
    public enum DecodeError: Error, Sendable, Equatable {
        case insufficientData
        case invalidFormat
    }

    /// Decodes a varint from the start of a byte array.
    /// - Parameter bytes: The bytes to decode from
    /// - Returns: A tuple of (decoded Varint, number of bytes consumed)
    /// - Throws: `DecodeError` if decoding fails
    public static func decode(from bytes: [UInt8]) throws(DecodeError) -> (Varint, Int) {
        guard let firstByte = bytes.first else {
            throw DecodeError.insufficientData
        }

        let prefix = firstByte >> 6
        let length: Int
        switch prefix {
        case 0b00: length = 1
        case 0b01: length = 2
        case 0b10: length = 4
        default:   length = 8  // 0b11
        }

        guard bytes.count >= length else {
            throw DecodeError.insufficientData
        }

        let value: UInt64
        switch length {
        case 1:
            value = UInt64(firstByte & 0x3F)
        case 2:
            value = UInt64(firstByte & 0x3F) << 8
                | UInt64(bytes[1])
        case 4:
            value = UInt64(firstByte & 0x3F) << 24
                | UInt64(bytes[1]) << 16
                | UInt64(bytes[2]) << 8
                | UInt64(bytes[3])
        default: // 8
            value = UInt64(firstByte & 0x3F) << 56
                | UInt64(bytes[1]) << 48
                | UInt64(bytes[2]) << 40
                | UInt64(bytes[3]) << 32
                | UInt64(bytes[4]) << 24
                | UInt64(bytes[5]) << 16
                | UInt64(bytes[6]) << 8
                | UInt64(bytes[7])
        }

        return (Varint(value), length)
    }

    /// Returns the encoded length for the first varint in the bytes without fully decoding.
    public static func peekEncodedLength(from bytes: [UInt8]) -> Int? {
        guard let firstByte = bytes.first else { return nil }
        let prefix = firstByte >> 6
        switch prefix {
        case 0b00: return 1
        case 0b01: return 2
        case 0b10: return 4
        case 0b11: return 8
        default: return nil
        }
    }
}

// MARK: - ExpressibleByIntegerLiteral

extension Varint: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt64) {
        self.init(value)
    }
}

// MARK: - CustomStringConvertible

extension Varint: CustomStringConvertible {
    public var description: String {
        "Varint(\(value))"
    }
}

// MARK: - Comparable

extension Varint: Comparable {
    public static func < (lhs: Varint, rhs: Varint) -> Bool {
        lhs.value < rhs.value
    }
}

// MARK: - Static Utilities

extension Varint {
    /// Returns the encoded length for a given value without creating a Varint instance
    ///
    /// This is useful for calculating frame sizes without allocating.
    ///
    /// - Parameter value: The value to check
    /// - Returns: The number of bytes needed to encode this value (1, 2, 4, or 8)
    @inlinable
    public static func encodedLength(for value: UInt64) -> Int {
        if value <= 63 {
            return 1
        } else if value <= 16383 {
            return 2
        } else if value <= 1_073_741_823 {
            return 4
        } else {
            return 8
        }
    }
}
