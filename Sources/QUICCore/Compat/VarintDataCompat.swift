/// `Data`-based convenience surface for the moved ``Varint`` type.
///
/// The Embedded-clean core exposes `encodeBytes() -> [UInt8]`,
/// `encode(to: inout ByteWriter)`, and `decode(from: [UInt8])`. This file
/// restores the historical `Data` API (`encode() -> Data`,
/// `encode(to: inout Data)`, `decode(from: Data)`, `peekEncodedLength(from: Data)`)
/// so existing callers and tests compile unchanged.

import Foundation
import QUICCoreCodec

extension Varint {
    /// Encodes the varint to `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Encodes the varint, appending to the given `Data`.
    public func encode(to data: inout Data) {
        data.append(contentsOf: encodeBytes())
    }

    /// Decodes a varint from the start of `Data`.
    /// - Returns: A tuple of (decoded Varint, number of bytes consumed).
    public static func decode(from data: Data) throws -> (Varint, Int) {
        try decode(from: [UInt8](data))
    }

    /// Returns the encoded length for the first varint in the data without fully decoding.
    public static func peekEncodedLength(from data: Data) -> Int? {
        peekEncodedLength(from: [UInt8](data))
    }
}
