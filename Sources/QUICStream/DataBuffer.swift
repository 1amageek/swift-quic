/// Stream Data Buffer (RFC 9000 Section 2.2)
///
/// `Data`-facing host adapter over the Embedded-clean `StreamReassemblyBuffer`
/// (`QUICStreamCore`). The reassembly logic — out-of-order insertion, overlap merging,
/// FIN / final-size validation, and contiguous extraction — lives in the core value
/// type over `[UInt8]`. This wrapper preserves the historical `Data`-based public API
/// (and the inspected `totalBytes` / `readOffset` / `finalSize` / `segmentCount`
/// surface), bridging `Data` to/from `[UInt8]`, so observable behavior is unchanged.

import Foundation
import QUICStreamCore

/// Ordered buffer for reassembling out-of-order stream data with FIN tracking.
public struct DataBuffer: Sendable {
    /// Maximum permitted stream final offset (RFC 9000 §4.5).
    static let maxFinalOffset: UInt64 = StreamReassemblyBuffer.maxFinalOffset

    /// The Embedded-clean reassembly core operating on `[UInt8]`.
    private var core: StreamReassemblyBuffer

    /// Creates an empty DataBuffer.
    /// - Parameter maxBufferSize: Maximum bytes to buffer (default 16MB).
    public init(maxBufferSize: UInt64 = 16 * 1024 * 1024) {
        self.core = StreamReassemblyBuffer(maxBufferSize: maxBufferSize)
    }

    /// Inserts data at the specified offset.
    /// - Throws: `DataBufferError` on validation failures.
    public mutating func insert(offset: UInt64, data: Data, fin: Bool) throws {
        try core.insert(offset: offset, data: [UInt8](data), fin: fin)
    }

    /// Reads and consumes contiguous data starting from readOffset.
    public mutating func readContiguous() -> Data? {
        core.readContiguous().map { Data($0) }
    }

    /// Peeks at contiguous data without consuming it.
    public func peekContiguous() -> Data? {
        core.peekContiguous().map { Data($0) }
    }

    /// Reads all available contiguous data (may span multiple merged segments).
    public mutating func readAllContiguous() -> Data? {
        core.readAllContiguous().map { Data($0) }
    }

    /// Resets the buffer to empty state.
    public mutating func reset() {
        core.reset()
    }

    // MARK: - Inspected state

    /// Total bytes stored in the buffer.
    var totalBytes: Int { core.totalBytes }

    /// Next byte offset to read (all prior bytes have been consumed).
    var readOffset: UInt64 { core.readOffset }

    /// Final size of the stream (known when FIN is received).
    var finalSize: UInt64? { core.finalSize }

    /// Whether there is a gap at the current read position.
    public var hasGap: Bool { core.hasGap }

    /// Whether all data has been received (FIN received and no gaps).
    public var isComplete: Bool { core.isComplete }

    /// Whether the final size is known (FIN was received).
    public var finalSizeKnown: Bool { core.finalSizeKnown }

    /// The number of bytes available to read (contiguous from readOffset).
    public var contiguousBytesAvailable: Int { core.contiguousBytesAvailable }

    /// Total buffered bytes (may include non-contiguous data).
    public var bufferedBytes: Int { core.bufferedBytes }

    /// Whether the buffer is empty.
    public var isEmpty: Bool { core.isEmpty }

    /// The number of segments in the buffer.
    public var segmentCount: Int { core.segmentCount }

    /// Bytes remaining until final size (nil if final size unknown).
    public var remainingBytes: UInt64? { core.remainingBytes }
}
