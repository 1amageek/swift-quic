/// Typed errors for the Embedded-clean stream cores (RFC 9000 Section 4).
///
/// These are protocol-security errors: a flow-control or final-size violation MUST
/// be surfaced to the caller (mapped to FLOW_CONTROL_ERROR / FINAL_SIZE_ERROR at the
/// connection layer) and never silently clamped or dropped.
///
/// Embedded-clean: no Foundation, no `any`. Closed enums; never silently swallowed.

/// Errors for reassembly-buffer operations.
public enum DataBufferError: Error, Sendable {
    /// Data exceeds the maximum buffer size.
    case bufferOverflow(maxSize: UInt64, requested: UInt64)
    /// FIN was already received at a different offset.
    case finalSizeMismatch(expected: UInt64, received: UInt64)
    /// Data received extends beyond the known final size.
    case dataExceedsFinalSize(finalSize: UInt64, receivedEnd: UInt64)
    /// The computed end offset (offset + length) overflows or exceeds 2^62-1
    /// (RFC 9000 §4.5 — final offset bound).
    case finalOffsetOutOfRange(offset: UInt64, length: UInt64)
}

/// Errors for stream send/receive operations.
public enum StreamError: Error, Sendable {
    /// Stream is in an invalid state for the operation.
    case invalidState(current: String, operation: String)
    /// Flow control violation.
    case flowControlViolation(limit: UInt64, requested: UInt64)
    /// Stream has been reset.
    case streamReset(errorCode: UInt64)
    /// Cannot send on receive-only stream.
    case cannotSendOnReceiveOnlyStream
    /// Cannot receive on send-only stream.
    case cannotReceiveOnSendOnlyStream
    /// Data buffer error.
    case bufferError(DataBufferError)
    /// Final size mismatch.
    case finalSizeMismatch(expected: UInt64, received: UInt64)
    /// Stream ID mismatch (internal error).
    case streamIDMismatch(expected: UInt64, received: UInt64)
}
