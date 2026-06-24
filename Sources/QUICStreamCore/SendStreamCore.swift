/// Send-stream state machine (RFC 9000 Section 3.1) as a value type.
///
/// Owns the send half of a QUIC stream: the send-side FSM
/// (Ready → Send → DataSent → DataRecvd, plus ResetSent / ResetRecvd), the outgoing
/// byte buffer with lazy compaction, the send offset / flow-control limit, and the
/// STOP_SENDING / RESET_STREAM bookkeeping. This is the byte-identical send logic of
/// the host `DataStream`, expressed as a `struct` with `mutating` methods over
/// `[UInt8]` payloads.
///
/// The host `DataStream` holds this under a `Mutex` and bridges `Data` to/from
/// `[UInt8]`, so observable behavior is unchanged. STREAM / RESET_STREAM frames are
/// the `[UInt8]`-based types from `QUICWire`.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

import QUICWire

public struct SendStreamCore: Sendable {
    /// Maximum permitted stream final offset (RFC 9000 §4.5): the stream final offset
    /// MUST stay within the QUIC varint range (2^62-1).
    public static let maxFinalOffset: UInt64 = (1 << 62) - 1

    /// Stream identifier.
    public let id: UInt64

    /// Whether this is a locally-initiated stream.
    public let isLocallyInitiated: Bool

    // MARK: - FSM / offset state

    /// Send state (for outgoing data).
    public private(set) var sendState: SendState

    /// Send offset (next byte to send / total bytes handed to frames).
    public private(set) var sendOffset: UInt64

    /// Send flow control limit (peer's MAX_STREAM_DATA).
    public private(set) var sendMaxData: UInt64

    /// Whether FIN has been sent.
    public private(set) var finSent: Bool

    // MARK: - Buffers / flags

    /// Send buffer (outgoing data queue).
    private var sendBuffer: [UInt8]

    /// Bytes consumed from the front of sendBuffer (lazy compaction).
    private var sendBufferConsumed: Int

    /// Offset of first unconsumed byte in the stream.
    private var sendBufferOffset: UInt64

    /// Whether FIN has been queued for sending.
    private var finQueued: Bool

    /// Whether we received STOP_SENDING from peer.
    public private(set) var stopSendingReceived: Bool

    /// Error code if STOP_SENDING received.
    public private(set) var stopSendingErrorCodeValue: UInt64?

    /// Whether we sent RESET_STREAM.
    public private(set) var resetStreamSent: Bool

    /// Error code if we sent RESET_STREAM.
    public private(set) var resetStreamErrorCode: UInt64?

    /// Creates a send-stream core.
    /// - Parameters:
    ///   - id: Stream identifier.
    ///   - isLocallyInitiated: Whether the local endpoint initiated the stream.
    ///   - initialSendMaxData: Initial send flow-control limit.
    public init(
        id: UInt64,
        isLocallyInitiated: Bool,
        initialSendMaxData: UInt64
    ) {
        self.id = id
        self.isLocallyInitiated = isLocallyInitiated
        self.sendState = .ready
        self.sendOffset = 0
        self.sendMaxData = initialSendMaxData
        self.finSent = false
        self.sendBuffer = []
        self.sendBufferConsumed = 0
        self.sendBufferOffset = 0
        self.finQueued = false
        self.stopSendingReceived = false
        self.stopSendingErrorCodeValue = nil
        self.resetStreamSent = false
        self.resetStreamErrorCode = nil
    }

    // MARK: - Derived state

    /// Whether the FSM permits sending.
    public var canSend: Bool {
        switch sendState {
        case .ready, .send:
            return true
        default:
            return false
        }
    }

    /// Whether this stream can send data (based on type and initiator).
    ///
    /// Bidirectional: both sides can send. Unidirectional: only the initiator can send.
    public var canSendOnStream: Bool {
        if StreamID.isBidirectional(id) {
            return canSend
        } else {
            return isLocallyInitiated && canSend
        }
    }

    /// Available send window.
    public var sendWindow: UInt64 {
        guard sendMaxData > sendOffset else { return 0 }
        return sendMaxData - sendOffset
    }

    /// Bytes pending to send.
    public var pendingSendBytes: Int {
        sendBuffer.count - sendBufferConsumed
    }

    /// Whether there's data to send (or a FIN still to flush).
    public var hasDataToSend: Bool {
        let pending = sendBuffer.count - sendBufferConsumed
        return pending > 0 || (finQueued && !finSent)
    }

    /// Whether this stream needs to generate a RESET_STREAM (due to STOP_SENDING).
    public var needsResetStream: Bool {
        stopSendingReceived && !resetStreamSent
    }

    /// The error code received in STOP_SENDING (if any).
    public var stopSendingErrorCode: UInt64? {
        stopSendingReceived ? stopSendingErrorCodeValue : nil
    }

    /// Whether the send side is closed.
    public var isSendClosed: Bool {
        sendState == .dataRecvd || sendState == .resetRecvd
    }

    // MARK: - Send operations

    /// Queue data for sending.
    /// - Parameter data: Data to send.
    /// - Throws: `StreamError` if stream cannot send.
    public mutating func write(_ data: [UInt8]) throws(StreamError) {
        // Check if we can send on this stream.
        if StreamID.isUnidirectional(id) && !isLocallyInitiated {
            throw StreamError.cannotSendOnReceiveOnlyStream
        }

        guard canSend else {
            throw StreamError.invalidState(
                current: stateDescription(sendState),
                operation: "write"
            )
        }

        if stopSendingReceived {
            throw StreamError.streamReset(errorCode: stopSendingErrorCodeValue ?? 0)
        }

        sendBuffer.append(contentsOf: data)

        // Transition to send state.
        if sendState == .ready {
            sendState = .send
        }
    }

    /// Mark stream as finished (queue FIN).
    /// - Throws: `StreamError` if stream cannot send.
    public mutating func finish() throws(StreamError) {
        if StreamID.isUnidirectional(id) && !isLocallyInitiated {
            throw StreamError.cannotSendOnReceiveOnlyStream
        }

        guard canSend else {
            throw StreamError.invalidState(
                current: stateDescription(sendState),
                operation: "finish"
            )
        }

        finQueued = true
    }

    /// Generate STREAM frames up to maxBytes.
    /// - Parameter maxBytes: Maximum total bytes for frames.
    /// - Returns: Array of STREAM frames to send.
    public mutating func generateFrames(maxBytes: Int) -> [StreamFrame] {
        let pending = sendBuffer.count - sendBufferConsumed
        guard pending > 0 || (finQueued && !finSent) else { return [] }

        var frames: [StreamFrame] = []
        var remainingBytes = maxBytes

        // Minimum overhead: streamID (1-8) + offset (0-8) + length (1-2) = ~11 bytes typical.
        let minOverhead = 11

        while remainingBytes > minOverhead {
            let currentPending = sendBuffer.count - sendBufferConsumed

            guard currentPending > 0 || (finQueued && !finSent) else { break }

            // Calculate how much data we can send.
            let availableWindow = sendMaxData > sendOffset ? sendMaxData - sendOffset : 0
            let dataInBuffer = UInt64(currentPending)
            // Use saturating subtraction to prevent underflow if remainingBytes < minOverhead.
            let adjustedRemaining = remainingBytes > minOverhead ? remainingBytes - minOverhead : 0
            let maxDataToSend = min(availableWindow, dataInBuffer, UInt64(adjustedRemaining))

            let dataToSend: [UInt8]
            let sendFin: Bool

            if maxDataToSend > 0 {
                // Extract data using consume offset (O(1) slice operation).
                let startIndex = sendBufferConsumed
                let endIndex = startIndex + Int(maxDataToSend)
                dataToSend = Array(sendBuffer[startIndex..<endIndex])
                sendBufferConsumed += Int(maxDataToSend)
                let newPending = sendBuffer.count - sendBufferConsumed
                sendFin = finQueued && newPending == 0
            } else if finQueued && !finSent && currentPending == 0 {
                // Send FIN-only frame.
                dataToSend = []
                sendFin = true
            } else {
                break  // No window or data.
            }

            let currentOffset = sendBufferOffset
            sendBufferOffset += UInt64(dataToSend.count)

            let frame = StreamFrame(
                streamID: id,
                offset: currentOffset,
                data: dataToSend,
                fin: sendFin,
                hasLength: true
            )
            frames.append(frame)

            // Update state.
            sendOffset = sendBufferOffset
            if sendFin {
                finSent = true
                sendState = .dataSent
            }

            // Safely subtract to track remaining bytes (saturate at 0).
            let consumed = minOverhead + dataToSend.count
            remainingBytes = remainingBytes > consumed ? remainingBytes - consumed : 0
        }

        // Compact buffer when consumed portion exceeds half the total size.
        // This amortizes the O(n) compaction cost.
        if sendBufferConsumed > sendBuffer.count / 2 && sendBufferConsumed > 4096 {
            sendBuffer.removeFirst(sendBufferConsumed)
            sendBufferConsumed = 0
        }

        return frames
    }

    // MARK: - Flow control

    /// Update send flow control limit (from MAX_STREAM_DATA).
    /// - Parameter maxData: New maximum data limit.
    public mutating func updateSendMaxData(_ maxData: UInt64) {
        if maxData > sendMaxData {
            sendMaxData = maxData
        }
    }

    // MARK: - Stream control frames

    /// Handle STOP_SENDING from peer.
    /// - Parameter errorCode: Application error code.
    ///
    /// RFC 9000 §3.5: an endpoint that receives STOP_SENDING MUST send RESET_STREAM.
    /// This sets the flag; RESET_STREAM is generated via `generateResetStream`.
    public mutating func handleStopSending(errorCode: UInt64) {
        stopSendingReceived = true
        stopSendingErrorCodeValue = errorCode

        // Clear send buffer (we won't be sending this data).
        sendBuffer.removeAll()
        sendBufferConsumed = 0

        // NOTE: Do NOT transition sendState here! The transition happens when
        // RESET_STREAM is actually generated, so the canSend check still passes.
    }

    /// Generate RESET_STREAM frame if needed.
    /// - Parameter errorCode: Application error code.
    /// - Returns: RESET_STREAM frame to send, or nil.
    ///
    /// RFC 9000 §3.5: RESET_STREAM can be generated when the stream can still send,
    /// has sent all data (dataSent), or the peer sent STOP_SENDING.
    public mutating func generateResetStream(errorCode: UInt64) -> ResetStreamFrame? {
        guard !resetStreamSent else { return nil }

        let canGenerate = canSend
            || sendState == .dataSent
            || stopSendingReceived
        guard canGenerate else { return nil }

        resetStreamSent = true
        resetStreamErrorCode = errorCode

        // Clear send buffer (may have been cleared by handleStopSending; safe to repeat).
        sendBuffer.removeAll()
        sendBufferConsumed = 0

        // Transition to resetSent state.
        sendState = .resetSent

        return ResetStreamFrame(
            streamID: id,
            applicationErrorCode: errorCode,
            finalSize: sendOffset
        )
    }

    // MARK: - Acknowledgement

    /// Acknowledge that peer received our data up to this offset.
    /// - Parameter offset: Acknowledged offset.
    public mutating func acknowledgeData(upTo offset: UInt64) {
        // If all sent data is acknowledged and FIN was sent.
        if offset >= sendOffset && finSent {
            sendState = .dataRecvd
        }
    }

    /// Acknowledge that peer received our RESET_STREAM.
    public mutating func acknowledgeReset() {
        if resetStreamSent {
            sendState = .resetRecvd
        }
    }

    // MARK: - Helpers

    /// Stable description of a send state for error reporting (matches the host's
    /// `String(describing:)` output for the `SendState` enum cases).
    private func stateDescription(_ state: SendState) -> String {
        switch state {
        case .ready: return "ready"
        case .send: return "send"
        case .dataSent: return "dataSent"
        case .dataRecvd: return "dataRecvd"
        case .resetSent: return "resetSent"
        case .resetRecvd: return "resetRecvd"
        }
    }
}
