import NetworkingCore

/// A borrowed, bounds-checked cursor for QUIC wire data.
///
/// The reader never owns or copies the input buffer. Owned arrays are created
/// only when a decoded protocol value must outlive this synchronous borrow.
public struct QUICWireReader: ~Escapable {
    private var cursor: ByteCursor

    @_lifetime(copy bytes)
    public init(_ bytes: Span<UInt8>) {
        cursor = ByteCursor(bytes)
    }

    @_lifetime(borrow bytes)
    public init(_ bytes: borrowing [UInt8]) {
        cursor = ByteCursor(bytes.span)
    }

    public var position: Int { cursor.offset }
    public var remaining: Int { cursor.remainingCount }
    public var isAtEnd: Bool { cursor.isAtEnd }

    public mutating func skip(_ count: Int) throws(ByteError) {
        try cursor.skip(count: count)
    }

    public mutating func readUInt8() throws(ByteError) -> UInt8 {
        try cursor.readByte()
    }

    public mutating func readUInt16() throws(ByteError) -> UInt16 {
        try cursor.readUInt16BigEndian()
    }

    public mutating func readUInt32() throws(ByteError) -> UInt32 {
        try cursor.readUInt32BigEndian()
    }

    public mutating func readUInt64() throws(ByteError) -> UInt64 {
        try cursor.readUInt64BigEndian()
    }

    public mutating func readBytes(_ count: Int) throws(ByteError) -> [UInt8] {
        let borrowed = try cursor.readSpan(count: count)
        var owned: [UInt8] = []
        owned.reserveCapacity(borrowed.count)
        borrowed.bytes.withUnsafeBytes { source in
            owned.append(contentsOf: source)
        }
        return owned
    }

    public mutating func readRemaining() throws(ByteError) -> [UInt8] {
        try readBytes(cursor.remainingCount)
    }

    public func peekUInt8() throws(ByteError) -> UInt8 {
        guard !cursor.isAtEnd else {
            throw .outOfBounds(offset: cursor.offset, requested: 1, available: 0)
        }
        return cursor.remainingSpan[0]
    }

    /// Reads a QUIC variable-length integer (RFC 9000 Section 16).
    public mutating func readVarint() throws(ByteError) -> UInt64 {
        let first = try cursor.readByte()
        let encodedLength = 1 << Int(first >> 6)
        var value = UInt64(first & 0x3F)
        var remainingBytes = encodedLength - 1
        while remainingBytes > 0 {
            value = (value << 8) | UInt64(try cursor.readByte())
            remainingBytes -= 1
        }
        return value
    }
}
