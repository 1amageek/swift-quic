/// Typed-throws wrappers over `P2PCoreBytes` reader/writer for the QUIC wire codec.
///
/// `ByteReader`/`ByteWriter` throw ``ByteError``; the QUIC codec throws
/// ``QUICWireError``. Embedded Swift requires typed throws end-to-end (no
/// `any Error`), and typed-throws does not auto-convert between error types, so
/// these thin wrappers rewrap `ByteError` as ``QUICWireError/bytes(_:)`` at each
/// call. They preserve the historical fast paths of the old `DataReader`
/// (single-byte varint, direct byte access) while operating on `[UInt8]`.

import P2PCoreBytes

extension ByteReader {
    @inline(__always)
    mutating func qReadUInt8() throws(QUICWireError) -> UInt8 {
        do { return try readUInt8() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func qReadUInt16() throws(QUICWireError) -> UInt16 {
        do { return try readUInt16() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func qReadUInt32() throws(QUICWireError) -> UInt32 {
        do { return try readUInt32() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func qReadUInt64() throws(QUICWireError) -> UInt64 {
        do { return try readUInt64() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func qReadBytes(_ count: Int) throws(QUICWireError) -> [UInt8] {
        do { return try readBytes(count) } catch { throw .bytes(error) }
    }

    /// Reads a QUIC variable-length integer (RFC 9000 §16), advancing the cursor.
    @inline(__always)
    mutating func qReadVarint() throws(QUICWireError) -> UInt64 {
        do { return try readVarint() } catch { throw .bytes(error) }
    }

    /// Reads all remaining bytes from the cursor.
    @inline(__always)
    mutating func qReadRemaining() -> [UInt8] {
        readRemaining()
    }
}

extension ByteWriter {
    /// Writes a QUIC variable-length integer (RFC 9000 §16).
    @inline(__always)
    mutating func qWriteVarint(_ value: UInt64) throws(QUICWireError) {
        do { try writeVarint(value) } catch { throw .bytes(error) }
    }

    /// Appends `count` zero bytes (PADDING frames, RFC 9000 §19.1).
    @inline(__always)
    mutating func qWriteZeroBytes(_ count: Int) {
        guard count > 0 else { return }
        writeBytes(repeatElement(UInt8(0), count: count))
    }
}
