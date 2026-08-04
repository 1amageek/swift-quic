/// CRYPTO Stream Reassembly
///
/// Reassembles out-of-order CRYPTO frames for TLS handshake data.

import Foundation
import QUICCore

/// Error thrown by CryptoStream operations
public enum CryptoStreamError: Error, Sendable {
    /// Buffer size limit exceeded
    case bufferExceeded(currentSize: Int, maxSize: Int)
    /// Invalid offset (negative or overflow)
    case invalidOffset(UInt64)
    /// A TLS handshake header declares a message larger than the policy limit.
    case messageTooLarge(actual: Int, maximum: Int)
    /// An overlapping range carried bytes different from data already received.
    case conflictingOverlap(offset: UInt64)
}

/// Reassembles out-of-order CRYPTO frames for a single encryption level
public struct CryptoStream: Sendable {
    /// Ordered buffer of received data
    private var buffer: CryptoBuffer

    /// Next expected offset (for in-order delivery)
    private var readOffset: UInt64

    /// Total bytes received (including consumed)
    private var totalReceived: UInt64

    /// Maximum buffer size (crypto buffer limit)
    private let maxBufferSize: UInt64

    /// Default maximum buffer size (16KB per RFC recommendation)
    public static let defaultMaxBufferSize: UInt64 = 16_384

    /// Creates a new CryptoStream
    /// - Parameter maxBufferSize: Maximum buffer size in bytes (default 16KB)
    public init(maxBufferSize: UInt64 = CryptoStream.defaultMaxBufferSize) {
        self.buffer = CryptoBuffer()
        self.readOffset = 0
        self.totalReceived = 0
        self.maxBufferSize = maxBufferSize
    }

    /// Receives a CRYPTO frame and buffers its data
    /// - Parameter frame: The received CRYPTO frame
    /// - Throws: `CryptoStreamError.bufferExceeded` if buffer limit exceeded
    public mutating func receive(_ frame: CryptoFrame) throws {
        guard !frame.data.isEmpty else { return }

        // Calculate end offset with overflow protection.
        let byteCount = UInt64(frame.data.count)
        guard frame.offset <= UInt64.max - byteCount else {
            throw CryptoStreamError.invalidOffset(frame.offset)
        }
        let endOffset = frame.offset + byteCount

        // Check if this would exceed buffer limit
        // Buffer limit is measured from read offset to end of buffered data
        let windowEnd = maxBufferSize > UInt64.max - readOffset
            ? UInt64.max
            : readOffset + maxBufferSize
        if endOffset > windowEnd {
            throw CryptoStreamError.bufferExceeded(
                currentSize: buffer.totalBytes,
                maxSize: maximumBufferSizeAsInt
            )
        }

        // Skip data we've already read
        if endOffset <= readOffset {
            // Entirely duplicate data - ignore
            return
        }

        // Trim leading bytes if they overlap with already-read data.
        // The frame's `data` is `[UInt8]` (Embedded-clean core); the crypto buffer
        // stores `Data`, so convert at this boundary.
        var dataToInsert = Data(frame.data)
        var insertOffset = frame.offset
        if frame.offset < readOffset {
            let skip = Int(readOffset - frame.offset)
            dataToInsert = Data(frame.data.dropFirst(skip))
            insertOffset = readOffset
        }

        // Insert into buffer
        try buffer.validateNoConflictingOverlap(offset: insertOffset, data: dataToInsert)
        buffer.insert(offset: insertOffset, data: dataToInsert)
        totalReceived += UInt64(dataToInsert.count)
    }

    /// Returns one complete TLS handshake message from readOffset.
    ///
    /// A partial header or body remains buffered and returns nil. The caller
    /// therefore never has to hand an incomplete message to the TLS session.
    public mutating func read() throws -> Data? {
        guard let data = buffer.readContiguous(from: readOffset) else {
            return nil
        }

        guard data.count >= 4 else { return nil }
        let bodyByteCount =
            (Int(data[data.startIndex + 1]) << 16) |
            (Int(data[data.startIndex + 2]) << 8) |
            Int(data[data.startIndex + 3])
        let messageByteCount = 4 + bodyByteCount
        guard messageByteCount <= maximumBufferSizeAsInt else {
            throw CryptoStreamError.messageTooLarge(
                actual: messageByteCount,
                maximum: maximumBufferSizeAsInt
            )
        }
        guard data.count >= messageByteCount else { return nil }

        // Consume the data
        let message = Data(data.prefix(messageByteCount))
        let newOffset = readOffset + UInt64(messageByteCount)
        buffer.consume(upTo: newOffset)
        readOffset = newOffset

        return message
    }

    /// Peek at next contiguous data without consuming
    /// - Returns: Contiguous data if available
    public func peek() -> Data? {
        buffer.peekContiguous(from: readOffset)
    }

    /// Current read offset
    public var currentOffset: UInt64 { readOffset }

    /// Whether there is pending data that cannot yet be read (gap exists)
    public var hasPendingGaps: Bool {
        buffer.hasDataAfter(readOffset) && peek() == nil
    }

    /// Whether the buffer is empty (all data has been read)
    public var isEmpty: Bool {
        buffer.isEmpty
    }

    /// The amount of buffered data not yet read
    public var bufferedBytes: Int {
        buffer.totalBytes
    }

    /// Converts the wire-independent UInt64 policy to the host `Int` domain
    /// without trapping on a 32-bit or adversarially configured target.
    private var maximumBufferSizeAsInt: Int {
        maxBufferSize > UInt64(Int.max) ? Int.max : Int(maxBufferSize)
    }
}
