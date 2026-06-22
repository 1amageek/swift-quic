/// `Data`-based convenience surface for the moved packet-header codec types.
///
/// The Embedded-clean core (`LongHeader`, `ShortHeader`, the `Protected*`
/// headers, `PacketNumberEncoding`) stores token / retry-integrity bytes as
/// `[UInt8]` and parses from `[UInt8]`. This file restores the historical
/// `Data`-accepting initializers, the `Data` views, the `parse(from: Data)`
/// overloads, and the `Data`-returning packet-number encoder so the packet
/// protection codec and the test suite compile unchanged.

import Foundation
import QUICCoreCodec

// MARK: - LongHeader Data conveniences

extension LongHeader {
    /// Creates a long header with a `Data`-typed token (and optional `Data`
    /// retry-integrity tag).
    ///
    /// `token` is intentionally a non-optional `Data` so a `token: nil` argument
    /// resolves unambiguously to the core `[UInt8]?` initializer, while a
    /// `Data`-typed token resolves here.
    public init(
        packetType: PacketType,
        version: QUICVersion,
        destinationConnectionID: ConnectionID,
        sourceConnectionID: ConnectionID,
        token: Data,
        retryIntegrityTag: Data? = nil,
        length: UInt64? = nil,
        packetNumber: UInt64 = 0,
        packetNumberLength: Int = 4
    ) {
        self.init(
            packetType: packetType,
            version: version,
            destinationConnectionID: destinationConnectionID,
            sourceConnectionID: sourceConnectionID,
            token: [UInt8](token),
            retryIntegrityTag: retryIntegrityTag.map { [UInt8]($0) },
            length: length,
            packetNumber: packetNumber,
            packetNumberLength: packetNumberLength
        )
    }

    /// The token as `Data`, if present.
    public var tokenData: Data? {
        token.map(Data.init)
    }

    /// The retry integrity tag as `Data`, if present.
    public var retryIntegrityTagData: Data? {
        retryIntegrityTag.map(Data.init)
    }
}

// MARK: - ProtectedLongHeader Data conveniences

extension ProtectedLongHeader {
    /// The token as `Data`, if present.
    public var tokenData: Data? {
        token.map(Data.init)
    }

    /// The retry integrity tag as `Data`, if present.
    public var retryIntegrityTagData: Data? {
        retryIntegrityTag.map(Data.init)
    }

    /// Parses a protected long header from `Data`.
    public static func parse(from data: Data) throws -> (ProtectedLongHeader, Int) {
        try parse(from: [UInt8](data))
    }
}

extension ProtectedShortHeader {
    /// Parses a protected short header from `Data`.
    public static func parse(from data: Data, dcidLength: Int) throws -> (ProtectedShortHeader, Int) {
        try parse(from: [UInt8](data), dcidLength: dcidLength)
    }
}

extension ProtectedPacketHeader {
    /// Parses a protected packet header from `Data`.
    public static func parse(from data: Data, dcidLength: Int = 0) throws -> (ProtectedPacketHeader, Int) {
        try parse(from: [UInt8](data), dcidLength: dcidLength)
    }
}

// MARK: - PacketNumberEncoding Data conveniences

extension PacketNumberEncoding {
    /// Encodes a packet number using the minimum number of bytes, returning `Data`.
    public static func encode(
        fullPacketNumber: UInt64,
        largestAcked: UInt64?
    ) -> (bytes: Data, length: Int) {
        let (bytes, length) = encodeBytes(fullPacketNumber: fullPacketNumber, largestAcked: largestAcked)
        return (Data(bytes), length)
    }
}
