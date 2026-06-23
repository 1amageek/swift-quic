/// Data Stream (RFC 9000 Section 2-3)
///
/// `Data`-facing, `Mutex`-held host adapter over the Embedded-clean stream cores
/// (`SendStreamCore` + `ReceiveStreamCore` in `QUICStreamCore`). The send/receive FSMs,
/// reassembly buffer, offset / flow-control accounting, and STOP_SENDING / RESET_STREAM
/// handling all live in those value-type cores over `[UInt8]`. This class owns
/// synchronization (one `Mutex` over both cores plus the mutable priority), bridges
/// `Data` to/from `[UInt8]`, and synthesizes the unified `StreamState` view, so the
/// public API and observable behavior are unchanged.
///
/// Bidirectional streams have both send and receive sides. Unidirectional streams have
/// only one side active.

import Foundation
import Synchronization
import QUICCore
import QUICStreamCore

/// Internal state for DataStream (protected by Mutex).
private struct DataStreamInternalState: Sendable {
    /// Send-stream FSM core.
    var send: SendStreamCore

    /// Receive-stream FSM core.
    var recv: ReceiveStreamCore

    /// Stream priority for scheduling.
    var priority: StreamPriority
}

/// A single QUIC stream with send/receive buffers.
public final class DataStream: Sendable {
    /// Maximum permitted stream final offset (RFC 9000 §4.5).
    static let maxFinalOffset: UInt64 = SendStreamCore.maxFinalOffset

    /// Stream identifier.
    public let id: UInt64

    /// Whether this is a locally-initiated stream.
    public let isLocallyInitiated: Bool

    /// Internal state protected by Mutex.
    private let _internal: Mutex<DataStreamInternalState>

    /// Creates a new DataStream.
    /// - Parameters:
    ///   - id: Stream identifier.
    ///   - isClient: Whether local endpoint is client.
    ///   - initialSendMaxData: Initial send flow control limit.
    ///   - initialRecvMaxData: Initial receive flow control limit.
    ///   - maxBufferSize: Maximum receive buffer size.
    ///   - priority: Initial stream priority (default: .default).
    public init(
        id: UInt64,
        isClient: Bool,
        initialSendMaxData: UInt64,
        initialRecvMaxData: UInt64,
        maxBufferSize: UInt64 = 16 * 1024 * 1024,
        priority: StreamPriority = .default
    ) {
        self.id = id

        // Determine if locally initiated.
        let isClientInitiated = StreamID.isClientInitiated(id)
        let locallyInitiated = (isClient && isClientInitiated) || (!isClient && !isClientInitiated)
        self.isLocallyInitiated = locallyInitiated

        self._internal = Mutex(DataStreamInternalState(
            send: SendStreamCore(
                id: id,
                isLocallyInitiated: locallyInitiated,
                initialSendMaxData: initialSendMaxData
            ),
            recv: ReceiveStreamCore(
                id: id,
                isLocallyInitiated: locallyInitiated,
                initialRecvMaxData: initialRecvMaxData,
                maxBufferSize: maxBufferSize
            ),
            priority: priority
        ))
    }

    // MARK: - Stream Properties

    /// Stream state machine (unified send + receive view).
    public var state: StreamState {
        _internal.withLock { Self.makeState($0) }
    }

    /// Synthesizes the unified `StreamState` from the send and receive cores.
    private static func makeState(_ s: DataStreamInternalState) -> StreamState {
        var st = StreamState(
            id: s.send.id,
            initialSendMaxData: s.send.sendMaxData,
            initialRecvMaxData: s.recv.recvMaxData
        )
        st.sendState = s.send.sendState
        st.recvState = s.recv.recvState
        st.sendOffset = s.send.sendOffset
        st.recvOffset = s.recv.recvOffset
        st.sendMaxData = s.send.sendMaxData
        st.recvMaxData = s.recv.recvMaxData
        st.finSent = s.send.finSent
        st.finReceived = s.recv.finReceived
        st.finalSize = s.recv.finalSize
        return st
    }

    /// Stream priority for scheduling (mutable).
    ///
    /// Streams with lower urgency values are scheduled first.
    public var priority: StreamPriority {
        get { _internal.withLock { $0.priority } }
        set { _internal.withLock { $0.priority = newValue } }
    }

    /// Whether this stream is bidirectional.
    public var isBidirectional: Bool {
        StreamID.isBidirectional(id)
    }

    /// Whether this stream is unidirectional.
    public var isUnidirectional: Bool {
        StreamID.isUnidirectional(id)
    }

    /// Whether this stream can send data (based on type and initiator).
    public var canSend: Bool {
        _internal.withLock { $0.send.canSendOnStream }
    }

    /// Whether this stream can receive data (based on type and initiator).
    public var canReceive: Bool {
        _internal.withLock { $0.recv.canReceiveOnStream }
    }

    /// Whether the stream is fully closed.
    public var isClosed: Bool {
        _internal.withLock { `internal` in
            let sendClosed = `internal`.send.isSendClosed
            let recvClosed = `internal`.recv.isReceiveClosed

            if StreamID.isBidirectional(id) {
                return sendClosed && recvClosed
            } else if isLocallyInitiated {
                return sendClosed  // Send-only
            } else {
                return recvClosed  // Receive-only
            }
        }
    }

    /// Available send window.
    public var sendWindow: UInt64 {
        _internal.withLock { $0.send.sendWindow }
    }

    /// Bytes pending to send.
    public var pendingSendBytes: Int {
        _internal.withLock { $0.send.pendingSendBytes }
    }

    /// Whether there's data to send.
    public var hasDataToSend: Bool {
        _internal.withLock { $0.send.hasDataToSend }
    }

    /// Whether there is data available to read.
    public var hasDataToRead: Bool {
        _internal.withLock { $0.recv.hasDataToRead }
    }

    /// Bytes buffered for reading.
    public var bufferedReadBytes: Int {
        _internal.withLock { $0.recv.bufferedReadBytes }
    }

    /// Whether this stream needs to generate a RESET_STREAM (due to STOP_SENDING received).
    public var needsResetStream: Bool {
        _internal.withLock { $0.send.needsResetStream }
    }

    /// The error code received in STOP_SENDING (if any).
    public var stopSendingErrorCode: UInt64? {
        _internal.withLock { $0.send.stopSendingErrorCode }
    }

    // MARK: - Receive Side

    /// Process incoming STREAM frame.
    /// - Parameter frame: The received STREAM frame.
    /// - Throws: `StreamError` on validation failures.
    public func receive(_ frame: StreamFrame) throws {
        try _internal.withLock { `internal` in
            try `internal`.recv.receive(frame)
        }
    }

    /// Read available contiguous data.
    /// - Returns: Data if available, nil otherwise.
    public func read() -> Data? {
        _internal.withLock { `internal` in
            `internal`.recv.read().map { Data($0) }
        }
    }

    /// Peek at available contiguous data without consuming.
    /// - Returns: Data if available, nil otherwise.
    public func peek() -> Data? {
        _internal.withLock { `internal` in
            `internal`.recv.peek().map { Data($0) }
        }
    }

    // MARK: - Send Side

    /// Queue data for sending.
    /// - Parameter data: Data to send.
    /// - Throws: `StreamError` if stream cannot send.
    public func write(_ data: Data) throws {
        try _internal.withLock { `internal` in
            try `internal`.send.write([UInt8](data))
        }
    }

    /// Mark stream as finished (queue FIN).
    /// - Throws: `StreamError` if stream cannot send.
    public func finish() throws {
        try _internal.withLock { `internal` in
            try `internal`.send.finish()
        }
    }

    /// Generate STREAM frames up to maxBytes.
    /// - Parameter maxBytes: Maximum total bytes for frames.
    /// - Returns: Array of STREAM frames to send.
    public func generateFrames(maxBytes: Int) -> [StreamFrame] {
        _internal.withLock { `internal` in
            `internal`.send.generateFrames(maxBytes: maxBytes)
        }
    }

    // MARK: - Flow Control Updates

    /// Update send flow control limit (from MAX_STREAM_DATA).
    /// - Parameter maxData: New maximum data limit.
    public func updateSendMaxData(_ maxData: UInt64) {
        _internal.withLock { `internal` in
            `internal`.send.updateSendMaxData(maxData)
        }
    }

    /// Update receive flow control limit.
    /// - Parameter maxData: New maximum data limit.
    public func updateRecvMaxData(_ maxData: UInt64) {
        _internal.withLock { `internal` in
            `internal`.recv.updateRecvMaxData(maxData)
        }
    }

    // MARK: - Stream Control Frames

    /// Handle STOP_SENDING from peer.
    /// - Parameter errorCode: Application error code.
    ///
    /// RFC 9000 §3.5: an endpoint that receives STOP_SENDING MUST send RESET_STREAM.
    /// This sets the flag; RESET_STREAM is generated via `generateResetStream`.
    public func handleStopSending(errorCode: UInt64) {
        _internal.withLock { `internal` in
            `internal`.send.handleStopSending(errorCode: errorCode)
        }
    }

    /// Handle RESET_STREAM from peer.
    /// - Parameters:
    ///   - errorCode: Application error code.
    ///   - finalSize: Final size of the stream.
    /// - Throws: `StreamError` if final size exceeds flow control limit or mismatches.
    public func handleResetStream(errorCode: UInt64, finalSize: UInt64) throws {
        try _internal.withLock { `internal` in
            try `internal`.recv.handleResetStream(errorCode: errorCode, finalSize: finalSize)
        }
    }

    /// Generate RESET_STREAM frame if needed.
    /// - Parameter errorCode: Application error code.
    /// - Returns: RESET_STREAM frame to send, or nil.
    public func generateResetStream(errorCode: UInt64) -> ResetStreamFrame? {
        _internal.withLock { `internal` in
            `internal`.send.generateResetStream(errorCode: errorCode)
        }
    }

    /// Generate STOP_SENDING frame.
    /// - Parameter errorCode: Application error code.
    /// - Returns: STOP_SENDING frame to send, or nil.
    public func generateStopSending(errorCode: UInt64) -> StopSendingFrame? {
        _internal.withLock { `internal` in
            `internal`.recv.generateStopSending(errorCode: errorCode)
        }
    }

    /// Acknowledge that peer received our data up to this offset.
    /// - Parameter offset: Acknowledged offset.
    public func acknowledgeData(upTo offset: UInt64) {
        _internal.withLock { `internal` in
            `internal`.send.acknowledgeData(upTo: offset)
        }
    }

    /// Acknowledge that peer received our RESET_STREAM.
    public func acknowledgeReset() {
        _internal.withLock { `internal` in
            `internal`.send.acknowledgeReset()
        }
    }
}
