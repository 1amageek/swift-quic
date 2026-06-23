/// Typed-throws wrappers over `P2PCoreBytes` reader/writer for the wire codec.
///
/// `ByteReader`/`ByteWriter` throw ``ByteError``; the handshake message/extension
/// codecs throw ``TLSWireError``. Embedded Swift requires typed throws end-to-end
/// (no `any Error`), and typed-throws does not auto-convert between error types, so
/// these thin wrappers rewrap `ByteError` as `TLSWireError.bytes` at each call.

import P2PCoreBytes

extension ByteReader {
    @inline(__always)
    mutating func wReadUInt8() throws(TLSWireError) -> UInt8 {
        do { return try readUInt8() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadUInt16() throws(TLSWireError) -> UInt16 {
        do { return try readUInt16() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadUInt24() throws(TLSWireError) -> UInt32 {
        do { return try readUInt24() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadUInt32() throws(TLSWireError) -> UInt32 {
        do { return try readUInt32() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadBytes(_ count: Int) throws(TLSWireError) -> [UInt8] {
        do { return try readBytes(count) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadVector8() throws(TLSWireError) -> [UInt8] {
        do { return try readVector8() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadVector16() throws(TLSWireError) -> [UInt8] {
        do { return try readVector16() } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wReadVector24() throws(TLSWireError) -> [UInt8] {
        do { return try readVector24() } catch { throw .bytes(error) }
    }
}

extension ByteWriter {
    @inline(__always)
    mutating func wWriteUInt24(_ value: UInt32) throws(TLSWireError) {
        do { try writeUInt24(value) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wWriteVector8(_ payload: [UInt8]) throws(TLSWireError) {
        do { try writeVector8(payload) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wWriteVector16(_ payload: [UInt8]) throws(TLSWireError) {
        do { try writeVector16(payload) } catch { throw .bytes(error) }
    }

    @inline(__always)
    mutating func wWriteVector24(_ payload: [UInt8]) throws(TLSWireError) {
        do { try writeVector24(payload) } catch { throw .bytes(error) }
    }
}
