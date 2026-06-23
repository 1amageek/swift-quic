/// Stream data reassembly buffer (RFC 9000 Section 2.2) as a value type.
///
/// Ordered buffer for reassembling out-of-order stream data with FIN tracking. This
/// is the byte-identical reassembly logic of the host `DataBuffer`, expressed as a
/// `struct` operating on `[UInt8]` payloads. The host `DataBuffer` wraps it and
/// bridges `Data` to/from `[UInt8]`, so observable behavior is unchanged.
///
/// This buffer handles:
/// - Out-of-order data insertion
/// - Overlapping segment detection and merging
/// - FIN tracking and final size validation (RFC 9000 §4.5)
/// - Contiguous data extraction
///
/// The final-offset bound, final-size mismatch, data-exceeds-final-size, and
/// buffer-overflow checks are protocol-security validations: they throw rather than
/// clamp or drop.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.
public struct StreamReassemblyBuffer: Sendable {
    /// Maximum permitted stream final offset (RFC 9000 §4.5): a QUIC varint can encode
    /// at most 2^62-1, and the stream final offset MUST stay within that range.
    public static let maxFinalOffset: UInt64 = (1 << 62) - 1

    /// Segments stored as (offset, data), sorted by offset.
    private var segments: [(offset: UInt64, data: [UInt8])] = []

    /// Total bytes stored in the buffer.
    public private(set) var totalBytes: Int = 0

    /// Next byte offset to read (all prior bytes have been consumed).
    public private(set) var readOffset: UInt64 = 0

    /// Final size of the stream (known when FIN is received).
    public private(set) var finalSize: UInt64?

    /// Maximum buffer size (prevents DoS).
    private let maxBufferSize: UInt64

    /// Creates an empty reassembly buffer.
    /// - Parameter maxBufferSize: Maximum bytes to buffer (default 16MB).
    public init(maxBufferSize: UInt64 = 16 * 1024 * 1024) {
        self.maxBufferSize = maxBufferSize
    }

    /// Inserts data at the specified offset.
    /// - Parameters:
    ///   - offset: The byte offset where this data starts.
    ///   - data: The data to insert.
    ///   - fin: Whether this is the final data (FIN flag).
    /// - Throws: `DataBufferError` on validation failures.
    public mutating func insert(offset: UInt64, data: [UInt8], fin: Bool) throws(DataBufferError) {
        // Empty data with FIN is valid (just marks the end).
        //
        // RFC 9000 §4.5: a stream's final offset (offset + length) MUST NOT exceed 2^62-1.
        // `offset` and `data.count` derive from untrusted wire data, so compute the end
        // offset with overflow reporting and reject an out-of-range result rather than
        // wrapping. This is the reassembly-layer chokepoint that mirrors the frame-decode
        // bound and also guards data produced internally.
        let (rawEndOffset, overflow) = offset.addingReportingOverflow(UInt64(data.count))
        guard !overflow, rawEndOffset <= Self.maxFinalOffset else {
            throw DataBufferError.finalOffsetOutOfRange(offset: offset, length: UInt64(data.count))
        }
        let endOffset = rawEndOffset

        // Validate FIN consistency.
        if fin {
            if let existingFinalSize = finalSize {
                guard existingFinalSize == endOffset else {
                    throw DataBufferError.finalSizeMismatch(
                        expected: existingFinalSize,
                        received: endOffset
                    )
                }
            } else {
                // Validate that no existing segments exceed the new final size.
                for segment in segments {
                    let segmentEnd = segment.offset + UInt64(segment.data.count)
                    if segmentEnd > endOffset {
                        throw DataBufferError.dataExceedsFinalSize(
                            finalSize: endOffset,
                            receivedEnd: segmentEnd
                        )
                    }
                }
                finalSize = endOffset
            }
        }

        // Check if data exceeds known final size.
        if let knownFinalSize = finalSize {
            guard endOffset <= knownFinalSize else {
                throw DataBufferError.dataExceedsFinalSize(
                    finalSize: knownFinalSize,
                    receivedEnd: endOffset
                )
            }
        }

        // Don't insert empty data (FIN was already processed above).
        guard !data.isEmpty else { return }

        // Skip data that's already been read.
        if endOffset <= readOffset {
            return  // Already consumed
        }

        // Trim data that partially overlaps with already-read portion.
        let insertOffset: UInt64
        let insertData: [UInt8]
        if offset < readOffset {
            let skipBytes = Int(readOffset - offset)
            insertOffset = readOffset
            insertData = Array(data.dropFirst(skipBytes))
        } else {
            insertOffset = offset
            insertData = data
        }

        // Check buffer overflow (using actual non-overlapping bytes).
        let actualNewBytes = calculateNonOverlappingBytes(insertOffset, insertData)
        let newTotal = UInt64(totalBytes) + actualNewBytes
        guard newTotal <= maxBufferSize else {
            throw DataBufferError.bufferOverflow(
                maxSize: maxBufferSize,
                requested: newTotal
            )
        }

        // Find insertion point (binary search for efficiency).
        let insertIndex = findInsertionIndex(for: insertOffset)

        // Insert the new segment.
        segments.insert((offset: insertOffset, data: insertData), at: insertIndex)
        totalBytes += insertData.count

        // Merge overlapping and adjacent segments.
        mergeSegments()
    }

    /// Finds the insertion index using binary search.
    private func findInsertionIndex(for offset: UInt64) -> Int {
        var low = 0
        var high = segments.count

        while low < high {
            let mid = (low + high) / 2
            if segments[mid].offset < offset {
                low = mid + 1
            } else {
                high = mid
            }
        }
        return low
    }

    /// Calculates non-overlapping bytes that would be added by new data.
    /// - Parameters:
    ///   - offset: The offset of the new data.
    ///   - data: The data to insert.
    /// - Returns: The number of bytes that don't overlap with existing segments.
    private func calculateNonOverlappingBytes(_ offset: UInt64, _ data: [UInt8]) -> UInt64 {
        guard !data.isEmpty else { return 0 }

        let endOffset = offset + UInt64(data.count)
        var nonOverlapping = UInt64(data.count)

        for segment in segments {
            let segmentEnd = segment.offset + UInt64(segment.data.count)
            // Calculate overlap range.
            let overlapStart = max(offset, segment.offset)
            let overlapEnd = min(endOffset, segmentEnd)
            if overlapStart < overlapEnd {
                nonOverlapping -= (overlapEnd - overlapStart)
            }
        }
        return nonOverlapping
    }

    /// Merges overlapping and adjacent segments.
    /// Uses delta tracking instead of recalculating totalBytes.
    private mutating func mergeSegments() {
        guard segments.count > 1 else { return }

        var merged: [(offset: UInt64, data: [UInt8])] = []
        merged.reserveCapacity(segments.count)
        var current = segments[0]
        var bytesRemoved = 0

        for i in 1..<segments.count {
            let next = segments[i]
            let currentEnd = current.offset + UInt64(current.data.count)

            if next.offset <= currentEnd {
                // Overlapping or adjacent - merge.
                let nextEnd = next.offset + UInt64(next.data.count)
                if nextEnd > currentEnd {
                    // Next segment extends beyond current.
                    let overlap = Int(currentEnd - next.offset)
                    bytesRemoved += overlap
                    let newData = next.data.dropFirst(overlap)
                    current = (
                        offset: current.offset,
                        data: current.data + newData
                    )
                } else {
                    // Next segment is completely contained - remove all its bytes.
                    bytesRemoved += next.data.count
                }
            } else {
                // Gap between segments.
                merged.append(current)
                current = next
            }
        }
        merged.append(current)

        totalBytes -= bytesRemoved
        segments = merged
    }

    /// Reads and consumes contiguous data starting from readOffset.
    /// - Returns: Contiguous data if available, nil if there's a gap or no data.
    public mutating func readContiguous() -> [UInt8]? {
        guard let first = segments.first else { return nil }

        // Check if data starts at the current read offset.
        guard first.offset == readOffset else { return nil }

        // Remove and return the first segment.
        segments.removeFirst()
        totalBytes -= first.data.count
        readOffset = first.offset + UInt64(first.data.count)

        return first.data
    }

    /// Peeks at contiguous data without consuming it.
    /// - Returns: Contiguous data if available, nil if there's a gap or no data.
    public func peekContiguous() -> [UInt8]? {
        guard let first = segments.first else { return nil }
        guard first.offset == readOffset else { return nil }
        return first.data
    }

    /// Reads all available contiguous data (may span multiple merged segments).
    /// - Returns: All contiguous data available, or nil if none.
    public mutating func readAllContiguous() -> [UInt8]? {
        guard let first = segments.first, first.offset == readOffset else {
            return nil
        }

        var result: [UInt8] = []
        result.reserveCapacity(totalBytes)

        while let first = segments.first, first.offset == readOffset {
            segments.removeFirst()
            result.append(contentsOf: first.data)
            readOffset = first.offset + UInt64(first.data.count)
        }

        totalBytes -= result.count
        return result.isEmpty ? nil : result
    }

    /// Whether there is a gap at the current read position.
    public var hasGap: Bool {
        guard let first = segments.first else {
            // No data at all - not a gap, just empty.
            return false
        }
        return first.offset > readOffset
    }

    /// Whether all data has been received (FIN received and no gaps).
    public var isComplete: Bool {
        guard let knownFinalSize = finalSize else { return false }
        return readOffset == knownFinalSize && segments.isEmpty
    }

    /// Whether the final size is known (FIN was received).
    public var finalSizeKnown: Bool {
        finalSize != nil
    }

    /// The number of bytes available to read (contiguous from readOffset).
    public var contiguousBytesAvailable: Int {
        guard let first = segments.first, first.offset == readOffset else {
            return 0
        }
        return first.data.count
    }

    /// Total buffered bytes (may include non-contiguous data).
    public var bufferedBytes: Int {
        totalBytes
    }

    /// Whether the buffer is empty.
    public var isEmpty: Bool {
        segments.isEmpty
    }

    /// The number of segments in the buffer.
    public var segmentCount: Int {
        segments.count
    }

    /// Bytes remaining until final size (nil if final size unknown).
    public var remainingBytes: UInt64? {
        guard let knownFinalSize = finalSize else { return nil }
        guard knownFinalSize >= readOffset else { return 0 }
        return knownFinalSize - readOffset
    }

    /// Resets the buffer to empty state.
    public mutating func reset() {
        segments.removeAll()
        totalBytes = 0
        readOffset = 0
        finalSize = nil
    }
}
