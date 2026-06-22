/// `Data`-based convenience surface for the moved ``QUICVersion`` type.
///
/// The Embedded-clean core exposes the initial-salt / retry-integrity constants
/// as `[UInt8]?` and encode/decode over `ByteReader`/`ByteWriter`. This file
/// restores the historical `Data?` views and the `encode(to: inout Data)` /
/// `decode(from: inout DataReader)` API so the crypto / version-negotiation
/// call sites compile unchanged.

import Foundation
import QUICCoreCodec

extension QUICVersion {
    /// Returns the initial salt for key derivation (RFC 9001 Section 5.2) as `Data`.
    public var initialSalt: Data? {
        initialSaltBytes.map(Data.init)
    }

    /// Returns the retry integrity key for this version as `Data`.
    public var retryIntegrityKey: Data? {
        retryIntegrityKeyBytes.map(Data.init)
    }

    /// Returns the retry integrity nonce for this version as `Data`.
    public var retryIntegrityNonce: Data? {
        retryIntegrityNonceBytes.map(Data.init)
    }

    /// Encodes the version as 4 bytes (big-endian), appending to `Data`.
    public func encode(to data: inout Data) {
        data.append(UInt8(rawValue >> 24))
        data.append(UInt8((rawValue >> 16) & 0xFF))
        data.append(UInt8((rawValue >> 8) & 0xFF))
        data.append(UInt8(rawValue & 0xFF))
    }

    /// Decodes a version from 4 bytes via the legacy `DataReader`.
    public static func decode(from reader: inout DataReader) -> QUICVersion? {
        guard let value = reader.readUInt32() else { return nil }
        return QUICVersion(rawValue: value)
    }
}
