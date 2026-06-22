/// `Data`-based convenience surface for the moved Frame codec types.
///
/// The Embedded-clean core (`Frame`, the frame structs, `StandardFrameCodec`)
/// stores byte payloads as `[UInt8]` and operates on `P2PCoreBytes`
/// `ByteReader`/`ByteWriter`. This file restores the historical `Data`-based
/// public API so existing call sites and the test suite compile unchanged:
///
/// - `Data`-accepting initializers on the frame structs (`CryptoFrame`,
///   `StreamFrame`, `DatagramFrame`, `NewConnectionIDFrame`).
/// - `Data`-returning encode (`encode(_:) -> Data`,
///   `encodeFrames(_:) -> Data`) and the legacy `DataReader`/`Data` decode
///   (`decode(from: inout DataReader)`, `decodeFrames(from: Data)`) on
///   `StandardFrameCodec`.
///
/// Frame enum cases carrying a direct byte payload (`.newToken`,
/// `.pathChallenge`, `.pathResponse`) have NO overload mechanism, so those
/// construction sites pass `[UInt8]` directly (Swift has no implicit
/// `Data -> [UInt8]`). Read-back comparisons (`frame.data == Data([...])`) are
/// served by the `[UInt8] == Data` overload in `BytesDataEquatableCompat`.

import Foundation
import P2PCoreBytes
import QUICCoreCodec

// MARK: - Frame struct Data conveniences

extension CryptoFrame {
    /// Creates a CRYPTO frame from `Data`.
    public init(offset: UInt64, data: Data) {
        self.init(offset: offset, data: [UInt8](data))
    }
}

extension StreamFrame {
    /// Creates a STREAM frame from `Data`.
    public init(
        streamID: UInt64,
        offset: UInt64,
        data: Data,
        fin: Bool = false,
        hasLength: Bool = true
    ) {
        self.init(
            streamID: streamID,
            offset: offset,
            data: [UInt8](data),
            fin: fin,
            hasLength: hasLength
        )
    }
}

extension DatagramFrame {
    /// Creates a DATAGRAM frame from `Data`.
    public init(data: Data, hasLength: Bool = true) {
        self.init(data: [UInt8](data), hasLength: hasLength)
    }
}

extension NewConnectionIDFrame {
    /// Creates a NEW_CONNECTION_ID frame from a `Data`-typed stateless reset token.
    public init(
        sequenceNumber: UInt64,
        retirePriorTo: UInt64,
        connectionID: ConnectionID,
        statelessResetToken: Data
    ) throws(FrameError) {
        try self.init(
            sequenceNumber: sequenceNumber,
            retirePriorTo: retirePriorTo,
            connectionID: connectionID,
            statelessResetToken: [UInt8](statelessResetToken)
        )
    }
}

// MARK: - StandardFrameCodec Data / DataReader conveniences

extension StandardFrameCodec {
    /// Encodes a single frame to `Data`.
    public func encode(_ frame: Frame) throws -> Data {
        Data(try encodeBytes(frame))
    }

    /// Encodes multiple frames to `Data`.
    public func encodeFrames(_ frames: [Frame]) throws -> Data {
        let bytes: [UInt8] = try encodeFrames(frames)
        return Data(bytes)
    }

    /// Decodes a single frame from the legacy `Data`-based `DataReader`.
    ///
    /// Bridges the `DataReader` cursor onto the Embedded-clean `ByteReader`
    /// decode path, then advances the `DataReader` by exactly the number of
    /// bytes the frame consumed so chained `decode(from:)` calls observe the
    /// same cursor semantics as before.
    public func decode(from reader: inout DataReader) throws -> Frame {
        let remaining = reader.remainingData
        var byteReader = ByteReader([UInt8](remaining))
        let frame = try decode(from: &byteReader)
        reader.advance(by: byteReader.position)
        return frame
    }

    /// Decodes all frames from `Data`.
    public func decodeFrames(from data: Data) throws -> [Frame] {
        try decodeFrames(from: [UInt8](data))
    }
}
