/// Receive-stream state machine (RFC 9000 Section 3.2) as a value type.
///
/// Owns the receive half of a QUIC stream: the receive-side FSM
/// (Recv → SizeKnown → DataRecvd → DataRead, plus ResetRecvd), the in-order
/// reassembly buffer, the receive offset / flow-control limit, and the final-size
/// bookkeeping. This is the byte-identical receive logic of the host `DataStream`,
/// expressed as a `struct` with `mutating` methods over `[UInt8]` payloads.
///
/// The host `DataStream` holds this under a `Mutex` and bridges `Data` to/from
/// `[UInt8]`, so observable behavior is unchanged.
///
/// The final-size (RFC 9000 §4.5) and flow-control (RFC 9000 §4.1) validations are
/// protocol-security checks: they throw `StreamError.finalSizeMismatch` /
/// `StreamError.flowControlViolation` rather than clamping or dropping.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

import QUICWire

public struct ReceiveStreamCore: Sendable {
    /// Maximum permitted stream final offset (RFC 9000 §4.5).
    public static let maxFinalOffset: UInt64 = (1 << 62) - 1

    /// Stream identifier.
    public let id: UInt64

    /// Whether this is a locally-initiated stream.
    public let isLocallyInitiated: Bool

    // MARK: - FSM / offset state

    /// Receive state (for incoming data).
    public private(set) var recvState: RecvState

    /// Receive offset (highest byte received).
    public private(set) var recvOffset: UInt64

    /// Receive flow control limit.
    public private(set) var recvMaxData: UInt64

    /// Whether FIN has been received.
    public private(set) var finReceived: Bool

    /// Final size (if known).
    public private(set) var finalSize: UInt64?

    /// Whether we received RESET_STREAM from peer.
    public private(set) var resetStreamReceived: Bool

    /// Error code if peer sent RESET_STREAM.
    public private(set) var peerResetErrorCode: UInt64?

    // MARK: - Buffer

    /// Receive buffer (incoming data reassembly).
    public private(set) var recvBuffer: StreamReassemblyBuffer

    /// Creates a receive-stream core.
    /// - Parameters:
    ///   - id: Stream identifier.
    ///   - isLocallyInitiated: Whether the local endpoint initiated the stream.
    ///   - initialRecvMaxData: Initial receive flow-control limit.
    ///   - maxBufferSize: Maximum receive buffer size.
    public init(
        id: UInt64,
        isLocallyInitiated: Bool,
        initialRecvMaxData: UInt64,
        maxBufferSize: UInt64
    ) {
        self.id = id
        self.isLocallyInitiated = isLocallyInitiated
        self.recvState = .recv
        self.recvOffset = 0
        self.recvMaxData = initialRecvMaxData
        self.finReceived = false
        self.finalSize = nil
        self.resetStreamReceived = false
        self.peerResetErrorCode = nil
        self.recvBuffer = StreamReassemblyBuffer(maxBufferSize: maxBufferSize)
    }

    // MARK: - Derived state

    /// Whether the FSM permits receiving.
    public var canReceive: Bool {
        switch recvState {
        case .recv, .sizeKnown:
            return true
        default:
            return false
        }
    }

    /// Whether this stream can receive data (based on type and initiator).
    ///
    /// Bidirectional: both sides can receive. Unidirectional: only the non-initiator
    /// can receive.
    public var canReceiveOnStream: Bool {
        if StreamID.isBidirectional(id) {
            return canReceive
        } else {
            return !isLocallyInitiated && canReceive
        }
    }

    /// Whether there is data available to read.
    public var hasDataToRead: Bool {
        recvBuffer.contiguousBytesAvailable > 0
    }

    /// Bytes buffered for reading.
    public var bufferedReadBytes: Int {
        recvBuffer.bufferedBytes
    }

    /// Whether the receive side is closed.
    public var isReceiveClosed: Bool {
        recvState == .dataRead || recvState == .resetRead
    }

    // MARK: - Receive operations

    /// Process incoming STREAM frame.
    /// - Parameter frame: The received STREAM frame.
    /// - Throws: `StreamError` on validation failures.
    public mutating func receive(_ frame: StreamFrame) throws(StreamError) {
        guard frame.streamID == id else {
            throw StreamError.streamIDMismatch(expected: id, received: frame.streamID)
        }

        // Check if we can receive on this stream.
        if StreamID.isUnidirectional(id) && isLocallyInitiated {
            throw StreamError.cannotReceiveOnSendOnlyStream
        }

        // RFC 9000 §4.5: the final size of a stream is invariant once established,
        // whether it was learned from a FIN-bearing STREAM frame or from RESET_STREAM.
        // Reconcile a FIN-bearing frame against any already-known final size BEFORE the
        // receive-state gate, so a FIN that contradicts a previously received
        // RESET_STREAM (or earlier FIN) is reported as FINAL_SIZE_ERROR rather than a
        // generic stream-state error. Use overflow-reporting arithmetic because the
        // offset and length are attacker-controlled wire values.
        let (computedEndOffset, endOffsetOverflow) =
            frame.offset.addingReportingOverflow(UInt64(frame.data.count))
        guard !endOffsetOverflow, computedEndOffset <= Self.maxFinalOffset else {
            throw StreamError.bufferError(
                .finalOffsetOutOfRange(offset: frame.offset, length: UInt64(frame.data.count))
            )
        }
        let endOffset = computedEndOffset

        if frame.fin, let knownFinalSize = finalSize {
            guard endOffset == knownFinalSize else {
                throw StreamError.finalSizeMismatch(
                    expected: knownFinalSize,
                    received: endOffset
                )
            }
        }

        guard canReceive else {
            throw StreamError.invalidState(
                current: stateDescription(recvState),
                operation: "receive"
            )
        }

        // Check receive flow control.
        if endOffset > recvMaxData {
            throw StreamError.flowControlViolation(
                limit: recvMaxData,
                requested: endOffset
            )
        }

        // Insert into buffer. `insert` is typed `throws(DataBufferError)`, so the bound
        // `error` is the concrete `DataBufferError` (no `any Error` boxing) and the
        // re-wrap into `StreamError.bufferError` is a plain enum construction. A bare
        // `catch` (no `as` pattern) is used to avoid the SILGen existential-ref path.
        do {
            try recvBuffer.insert(offset: frame.offset, data: frame.data, fin: frame.fin)
        } catch {
            throw StreamError.bufferError(error)
        }

        // Update state for FIN.
        if frame.fin {
            finReceived = true
            finalSize = endOffset
            recvState = .sizeKnown
        }

        // Update receive offset tracking (highest byte received).
        if endOffset > recvOffset {
            recvOffset = endOffset
        }
    }

    /// Read available contiguous data.
    /// - Returns: Data if available, nil otherwise.
    public mutating func read() -> [UInt8]? {
        let canRecv = StreamID.isBidirectional(id)
            ? canReceive
            : (!isLocallyInitiated && canReceive)

        guard canRecv || recvState == .sizeKnown || recvState == .dataRecvd else {
            return nil
        }

        let data = recvBuffer.readAllContiguous()

        // Update state if all data has been read.
        if recvBuffer.isComplete && finReceived {
            recvState = .dataRead
        } else if data != nil && recvState == .sizeKnown && recvBuffer.isEmpty {
            recvState = .dataRecvd
        }

        return data
    }

    /// Peek at available contiguous data without consuming.
    /// - Returns: Data if available, nil otherwise.
    public func peek() -> [UInt8]? {
        recvBuffer.peekContiguous()
    }

    // MARK: - Flow control

    /// Update receive flow control limit.
    /// - Parameter maxData: New maximum data limit.
    public mutating func updateRecvMaxData(_ maxData: UInt64) {
        if maxData > recvMaxData {
            recvMaxData = maxData
        }
    }

    // MARK: - Stream control frames

    /// Handle RESET_STREAM from peer.
    /// - Parameters:
    ///   - errorCode: Application error code.
    ///   - finalSize: Final size of the stream.
    /// - Throws: `StreamError` if final size exceeds flow control limit or mismatches.
    public mutating func handleResetStream(errorCode: UInt64, finalSize: UInt64) throws(StreamError) {
        // RFC 9000 §4.5: validate final size against flow control limit.
        if finalSize > recvMaxData {
            throw StreamError.flowControlViolation(
                limit: recvMaxData,
                requested: finalSize
            )
        }

        // Validate final size if already known.
        if let knownFinalSize = self.finalSize {
            guard finalSize == knownFinalSize else {
                throw StreamError.finalSizeMismatch(
                    expected: knownFinalSize,
                    received: finalSize
                )
            }
        }

        resetStreamReceived = true
        peerResetErrorCode = errorCode
        self.finalSize = finalSize

        // Clear receive buffer.
        recvBuffer.reset()

        // Transition receive state.
        recvState = .resetRecvd
    }

    /// Generate STOP_SENDING frame.
    /// - Parameter errorCode: Application error code.
    /// - Returns: STOP_SENDING frame to send, or nil.
    public func generateStopSending(errorCode: UInt64) -> StopSendingFrame? {
        let canRecv = StreamID.isBidirectional(id)
            ? canReceive
            : (!isLocallyInitiated && canReceive)

        guard canRecv else { return nil }

        return StopSendingFrame(
            streamID: id,
            applicationErrorCode: errorCode
        )
    }

    // MARK: - Helpers

    /// Stable description of a receive state for error reporting (matches the host's
    /// `String(describing:)` output for the `RecvState` enum cases).
    private func stateDescription(_ state: RecvState) -> String {
        switch state {
        case .recv: return "recv"
        case .sizeKnown: return "sizeKnown"
        case .dataRecvd: return "dataRecvd"
        case .dataRead: return "dataRead"
        case .resetRecvd: return "resetRecvd"
        case .resetRead: return "resetRead"
        }
    }
}
