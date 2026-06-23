/// Flow Controller (RFC 9000 Section 4)
///
/// Host wrapper over the Embedded-clean `FlowControllerCore` (`QUICStreamCore`). The
/// connection-level and stream-level credit accounting, window-update thresholds,
/// blocked detection, and stream-concurrency limits all live in the core value type.
/// This wrapper preserves the historical public API and the inspected
/// `connectionBytesReceived` / `connectionBlocked` / `connectionSendWindow` surface,
/// delegating to the core, so observable behavior is unchanged.

import QUICCore
import QUICStreamCore

/// Connection and stream-level flow control.
///
/// QUIC uses credit-based flow control similar to HTTP/2. The receiver advertises the
/// maximum amount of data the sender can send.
public struct FlowController: Sendable {
    /// The Embedded-clean flow-control accounting core.
    private var core: FlowControllerCore

    /// Creates a new FlowController.
    public init(
        isClient: Bool,
        initialMaxData: UInt64 = 1024 * 1024,
        initialMaxStreamDataBidiLocal: UInt64 = 256 * 1024,
        initialMaxStreamDataBidiRemote: UInt64 = 256 * 1024,
        initialMaxStreamDataUni: UInt64 = 256 * 1024,
        initialMaxStreamsBidi: UInt64 = 100,
        initialMaxStreamsUni: UInt64 = 100,
        peerMaxData: UInt64 = 0,
        peerMaxStreamsBidi: UInt64 = 0,
        peerMaxStreamsUni: UInt64 = 0,
        autoUpdateThreshold: Double = 0.5
    ) {
        self.core = FlowControllerCore(
            isClient: isClient,
            initialMaxData: initialMaxData,
            initialMaxStreamDataBidiLocal: initialMaxStreamDataBidiLocal,
            initialMaxStreamDataBidiRemote: initialMaxStreamDataBidiRemote,
            initialMaxStreamDataUni: initialMaxStreamDataUni,
            initialMaxStreamsBidi: initialMaxStreamsBidi,
            initialMaxStreamsUni: initialMaxStreamsUni,
            peerMaxData: peerMaxData,
            peerMaxStreamsBidi: peerMaxStreamsBidi,
            peerMaxStreamsUni: peerMaxStreamsUni,
            autoUpdateThreshold: autoUpdateThreshold
        )
    }

    // MARK: - Initial stream data limits (read-only mirrors)

    public var initialMaxStreamDataBidiLocal: UInt64 { core.initialMaxStreamDataBidiLocal }
    public var initialMaxStreamDataBidiRemote: UInt64 { core.initialMaxStreamDataBidiRemote }
    public var initialMaxStreamDataUni: UInt64 { core.initialMaxStreamDataUni }

    // MARK: - Inspected connection-level state

    var connectionBytesReceived: UInt64 { core.connectionBytesReceived }
    var connectionBlocked: Bool { core.connectionBlocked }

    // MARK: - Connection-Level Flow Control

    public func canReceive(bytes: UInt64) -> Bool {
        core.canReceive(bytes: bytes)
    }

    public mutating func recordBytesReceived(_ bytes: UInt64) {
        core.recordBytesReceived(bytes)
    }

    public func canSend(bytes: UInt64) -> Bool {
        core.canSend(bytes: bytes)
    }

    public mutating func recordBytesSent(_ bytes: UInt64) {
        core.recordBytesSent(bytes)
    }

    public var connectionSendWindow: UInt64 {
        core.connectionSendWindow
    }

    public mutating func updateConnectionSendLimit(_ maxData: UInt64) {
        core.updateConnectionSendLimit(maxData)
    }

    public mutating func generateMaxData() -> MaxDataFrame? {
        core.generateMaxData()
    }

    public func generateDataBlocked() -> DataBlockedFrame? {
        core.generateDataBlocked()
    }

    // MARK: - Stream-Level Flow Control

    public func canReceiveOnStream(_ streamID: UInt64, endOffset: UInt64) -> Bool {
        core.canReceiveOnStream(streamID, endOffset: endOffset)
    }

    public func streamBytesReceived(for streamID: UInt64) -> UInt64 {
        core.streamBytesReceived(for: streamID)
    }

    @discardableResult
    public mutating func recordStreamBytesReceived(_ streamID: UInt64, endOffset: UInt64) -> UInt64 {
        core.recordStreamBytesReceived(streamID, endOffset: endOffset)
    }

    public mutating func initializeStream(_ streamID: UInt64) {
        core.initializeStream(streamID)
    }

    public mutating func updateStreamRecvLimit(_ streamID: UInt64, maxData: UInt64) {
        core.updateStreamRecvLimit(streamID, maxData: maxData)
    }

    public mutating func generateMaxStreamData(for streamID: UInt64) -> MaxStreamDataFrame? {
        core.generateMaxStreamData(for: streamID)
    }

    public mutating func removeStream(_ streamID: UInt64) {
        core.removeStream(streamID)
    }

    public var trackedStreamIDs: [UInt64] {
        core.trackedStreamIDs
    }

    // MARK: - Stream Concurrency

    public func canOpenStream(bidirectional: Bool) -> Bool {
        core.canOpenStream(bidirectional: bidirectional)
    }

    public mutating func recordLocalStreamOpened(bidirectional: Bool) {
        core.recordLocalStreamOpened(bidirectional: bidirectional)
    }

    public mutating func recordLocalStreamClosed(bidirectional: Bool) {
        core.recordLocalStreamClosed(bidirectional: bidirectional)
    }

    public func canAcceptRemoteStream(bidirectional: Bool) -> Bool {
        core.canAcceptRemoteStream(bidirectional: bidirectional)
    }

    public mutating func recordRemoteStreamOpened(bidirectional: Bool) {
        core.recordRemoteStreamOpened(bidirectional: bidirectional)
    }

    public mutating func recordRemoteStreamClosed(bidirectional: Bool) {
        core.recordRemoteStreamClosed(bidirectional: bidirectional)
    }

    public mutating func updateRemoteStreamLimit(_ maxStreams: UInt64, bidirectional: Bool) {
        core.updateRemoteStreamLimit(maxStreams, bidirectional: bidirectional)
    }

    public mutating func generateMaxStreams(bidirectional: Bool) -> MaxStreamsFrame? {
        core.generateMaxStreams(bidirectional: bidirectional)
    }

    public func generateStreamsBlocked(bidirectional: Bool) -> StreamsBlockedFrame? {
        core.generateStreamsBlocked(bidirectional: bidirectional)
    }
}
