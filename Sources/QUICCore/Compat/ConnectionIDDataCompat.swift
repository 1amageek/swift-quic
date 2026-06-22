/// `Data`-based convenience surface for the moved ``ConnectionID`` type.
///
/// The Embedded-clean core stores `bytes` as `[UInt8]` and exposes encode/decode
/// over `ByteReader`/`ByteWriter`. This file restores the historical
/// `init(bytes: Data)`, the `Data` views, and the `Data`-based encode plus the
/// legacy `DataReader` decode so existing callers and tests compile unchanged.

import Foundation
import QUICCoreCodec

extension ConnectionID {
    /// Creates a connection ID from `Data` with validation.
    public init(bytes data: Data) throws(ConnectionIDError) {
        try self.init(bytes: [UInt8](data))
    }

    /// The raw bytes of the connection ID as `Data`.
    public var bytesData: Data {
        Data(bytes)
    }

    /// Encodes the connection ID (length byte + data) to `Data`.
    public func encode() -> Data {
        Data(encodeBytes())
    }

    /// Encodes the connection ID (length byte + data), appending to `Data`.
    public func encode(to data: inout Data) {
        data.append(UInt8(bytes.count))
        data.append(contentsOf: bytes)
    }

    /// Encodes only the bytes (without length prefix), appending to `Data`.
    public func encodeBytes(to data: inout Data) {
        data.append(contentsOf: bytes)
    }

    /// Decodes a connection ID (reads length byte + data) via the legacy `DataReader`.
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
        return try ConnectionID(bytes: bytes)
    }

    /// Decodes connection ID bytes (without length prefix) given a known length,
    /// via the legacy `DataReader`.
    public static func decodeBytes(from reader: inout DataReader, length: Int) throws -> ConnectionID {
        guard length <= maxLength else {
            throw DecodeError.invalidLength(length)
        }
        guard length > 0 else { return .empty }
        guard let bytes = reader.readBytes(length) else {
            throw DecodeError.insufficientData
        }
        return try ConnectionID(bytes: bytes)
    }
}
