/// Flow controller core (RFC 9000 Section 4) as a value type.
///
/// Connection-level and stream-level credit-based flow control, plus stream-concurrency
/// accounting (MAX_STREAMS / STREAMS_BLOCKED). This is the byte-identical accounting of
/// the host `FlowController`, expressed as a `struct` with `mutating` methods. The host
/// `FlowController` wraps it and exposes the same public API, so observable behavior —
/// including window-update thresholds, blocked detection, and overflow saturation — is
/// unchanged.
///
/// QUIC uses credit-based flow control similar to HTTP/2: the receiver advertises the
/// maximum amount of data the sender can send. The frame types returned here
/// (MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS / DATA_BLOCKED / STREAMS_BLOCKED) are the
/// Embedded-clean codec types from `QUICCoreCodec`.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

import QUICCoreCodec

public struct FlowControllerCore: Sendable {
    // MARK: - Role

    /// Whether this endpoint is the client.
    private let isClient: Bool

    // MARK: - Connection-Level Receive Side

    /// Total bytes received across all streams.
    public private(set) var connectionBytesReceived: UInt64

    /// Maximum bytes we allow peer to send (our receive window).
    public private(set) var connectionRecvLimit: UInt64

    /// Initial connection receive limit (for calculating when to send MAX_DATA).
    private let initialConnectionRecvLimit: UInt64

    /// Threshold for sending MAX_DATA (percentage of window consumed).
    private let autoUpdateThreshold: Double

    // MARK: - Connection-Level Send Side

    /// Total bytes sent across all streams.
    public private(set) var connectionBytesSent: UInt64

    /// Maximum bytes peer allows us to send (peer's receive window).
    public private(set) var connectionSendLimit: UInt64

    /// Whether we're currently blocked on connection-level flow control.
    public private(set) var connectionBlocked: Bool

    // MARK: - Stream Limits

    /// Maximum bidirectional streams we allow peer to open.
    public private(set) var maxLocalBidiStreams: UInt64

    /// Maximum unidirectional streams we allow peer to open.
    public private(set) var maxLocalUniStreams: UInt64

    /// Maximum bidirectional streams peer allows us to open.
    public private(set) var maxRemoteBidiStreams: UInt64

    /// Maximum unidirectional streams peer allows us to open.
    public private(set) var maxRemoteUniStreams: UInt64

    /// Current count of locally-opened bidirectional streams.
    public private(set) var openLocalBidiStreams: UInt64

    /// Current count of locally-opened unidirectional streams.
    public private(set) var openLocalUniStreams: UInt64

    /// Current count of remotely-opened bidirectional streams.
    public private(set) var openRemoteBidiStreams: UInt64

    /// Current count of remotely-opened unidirectional streams.
    public private(set) var openRemoteUniStreams: UInt64

    /// Initial stream data limit for locally-initiated bidirectional streams.
    public let initialMaxStreamDataBidiLocal: UInt64

    /// Initial stream data limit for remotely-initiated bidirectional streams.
    public let initialMaxStreamDataBidiRemote: UInt64

    /// Initial stream data limit for unidirectional streams.
    public let initialMaxStreamDataUni: UInt64

    /// Per-stream receive limits (stream ID -> current limit).
    private var streamRecvLimits: [UInt64: UInt64]

    /// Per-stream bytes received (stream ID -> bytes received).
    private var streamBytesReceivedMap: [UInt64: UInt64]

    // MARK: - Initialization

    /// Creates a new FlowControllerCore.
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
        self.isClient = isClient
        self.connectionBytesReceived = 0
        self.connectionRecvLimit = initialMaxData
        self.initialConnectionRecvLimit = initialMaxData
        self.autoUpdateThreshold = autoUpdateThreshold

        self.connectionBytesSent = 0
        self.connectionSendLimit = peerMaxData
        self.connectionBlocked = false

        self.maxLocalBidiStreams = initialMaxStreamsBidi
        self.maxLocalUniStreams = initialMaxStreamsUni
        self.maxRemoteBidiStreams = peerMaxStreamsBidi
        self.maxRemoteUniStreams = peerMaxStreamsUni

        self.openLocalBidiStreams = 0
        self.openLocalUniStreams = 0
        self.openRemoteBidiStreams = 0
        self.openRemoteUniStreams = 0

        self.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal
        self.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote
        self.initialMaxStreamDataUni = initialMaxStreamDataUni

        self.streamRecvLimits = [:]
        self.streamBytesReceivedMap = [:]
    }

    // MARK: - Connection-Level Flow Control

    /// Check if we can receive more data on the connection.
    public func canReceive(bytes: UInt64) -> Bool {
        let (total, overflow) = connectionBytesReceived.addingReportingOverflow(bytes)
        if overflow { return false }
        return total <= connectionRecvLimit
    }

    /// Record bytes received on the connection (saturating).
    public mutating func recordBytesReceived(_ bytes: UInt64) {
        let (total, overflow) = connectionBytesReceived.addingReportingOverflow(bytes)
        connectionBytesReceived = overflow ? UInt64.max : total
    }

    /// Check if we can send more data on the connection.
    public func canSend(bytes: UInt64) -> Bool {
        let (total, overflow) = connectionBytesSent.addingReportingOverflow(bytes)
        if overflow { return false }
        return total <= connectionSendLimit
    }

    /// Record bytes sent on the connection (saturating).
    public mutating func recordBytesSent(_ bytes: UInt64) {
        let (total, overflow) = connectionBytesSent.addingReportingOverflow(bytes)
        connectionBytesSent = overflow ? UInt64.max : total
        if connectionBytesSent >= connectionSendLimit {
            connectionBlocked = true
        }
    }

    /// Available connection-level send window.
    public var connectionSendWindow: UInt64 {
        guard connectionSendLimit > connectionBytesSent else { return 0 }
        return connectionSendLimit - connectionBytesSent
    }

    /// Update connection send limit (from peer's MAX_DATA).
    public mutating func updateConnectionSendLimit(_ maxData: UInt64) {
        if maxData > connectionSendLimit {
            connectionSendLimit = maxData
            connectionBlocked = false
        }
    }

    /// Generate MAX_DATA frame if needed.
    public mutating func generateMaxData() -> MaxDataFrame? {
        guard connectionRecvLimit >= connectionBytesReceived else {
            // Already exceeded limit - shouldn't happen but protect against it.
            return nil
        }
        let remaining = connectionRecvLimit - connectionBytesReceived
        let threshold = UInt64(Double(initialConnectionRecvLimit) * autoUpdateThreshold)

        if remaining < threshold {
            let (newLimit, overflow) = connectionRecvLimit.addingReportingOverflow(initialConnectionRecvLimit)
            connectionRecvLimit = overflow ? UInt64.max : newLimit
            return MaxDataFrame(maxData: connectionRecvLimit)
        }

        return nil
    }

    /// Generate DATA_BLOCKED frame if needed.
    public func generateDataBlocked() -> DataBlockedFrame? {
        if connectionBlocked {
            return DataBlockedFrame(dataLimit: connectionSendLimit)
        }
        return nil
    }

    // MARK: - Stream-Level Flow Control

    /// Check if we can receive data on a stream.
    public func canReceiveOnStream(_ streamID: UInt64, endOffset: UInt64) -> Bool {
        guard let limit = streamRecvLimits[streamID] else {
            return endOffset <= getInitialStreamLimit(for: streamID)
        }
        return endOffset <= limit
    }

    /// Get the highest offset received on a stream.
    public func streamBytesReceived(for streamID: UInt64) -> UInt64 {
        streamBytesReceivedMap[streamID] ?? 0
    }

    /// Record bytes received on a stream.
    /// - Returns: The number of NEW bytes (not previously counted for flow control).
    @discardableResult
    public mutating func recordStreamBytesReceived(_ streamID: UInt64, endOffset: UInt64) -> UInt64 {
        let current = streamBytesReceivedMap[streamID] ?? 0
        if endOffset > current {
            let newBytes = endOffset - current
            streamBytesReceivedMap[streamID] = endOffset
            return newBytes
        }
        return 0
    }

    /// Initialize stream flow control.
    public mutating func initializeStream(_ streamID: UInt64) {
        if streamRecvLimits[streamID] == nil {
            streamRecvLimits[streamID] = getInitialStreamLimit(for: streamID)
            streamBytesReceivedMap[streamID] = 0
        }
    }

    /// Get initial stream limit based on stream type and initiator.
    private func getInitialStreamLimit(for streamID: UInt64) -> UInt64 {
        if StreamID.isUnidirectional(streamID) {
            return initialMaxStreamDataUni
        } else {
            let isClientInitiated = StreamID.isClientInitiated(streamID)
            let isLocal = (isClient && isClientInitiated) || (!isClient && !isClientInitiated)
            return isLocal ? initialMaxStreamDataBidiLocal : initialMaxStreamDataBidiRemote
        }
    }

    /// Update stream receive limit.
    public mutating func updateStreamRecvLimit(_ streamID: UInt64, maxData: UInt64) {
        let current = streamRecvLimits[streamID] ?? 0
        if maxData > current {
            streamRecvLimits[streamID] = maxData
        }
    }

    /// Generate MAX_STREAM_DATA frame if needed for a stream.
    public mutating func generateMaxStreamData(for streamID: UInt64) -> MaxStreamDataFrame? {
        guard let limit = streamRecvLimits[streamID],
              let received = streamBytesReceivedMap[streamID] else {
            return nil
        }

        guard limit >= received else { return nil }
        let remaining = limit - received
        let initialLimit = getInitialStreamLimit(for: streamID)
        let threshold = UInt64(Double(initialLimit) * autoUpdateThreshold)

        if remaining < threshold {
            let (newLimit, overflow) = limit.addingReportingOverflow(initialLimit)
            let safeLimit = overflow ? UInt64.max : newLimit
            streamRecvLimits[streamID] = safeLimit
            return MaxStreamDataFrame(streamID: streamID, maxStreamData: safeLimit)
        }

        return nil
    }

    /// Remove stream from tracking (when closed).
    public mutating func removeStream(_ streamID: UInt64) {
        streamRecvLimits.removeValue(forKey: streamID)
        streamBytesReceivedMap.removeValue(forKey: streamID)
    }

    /// Get all tracked stream IDs (for cleanup on connection close).
    public var trackedStreamIDs: [UInt64] {
        Array(streamRecvLimits.keys)
    }

    // MARK: - Stream Concurrency

    /// Check if we can open a new locally-initiated stream.
    public func canOpenStream(bidirectional: Bool) -> Bool {
        if bidirectional {
            return openLocalBidiStreams < maxRemoteBidiStreams
        } else {
            return openLocalUniStreams < maxRemoteUniStreams
        }
    }

    /// Record opening a local stream.
    public mutating func recordLocalStreamOpened(bidirectional: Bool) {
        if bidirectional {
            openLocalBidiStreams += 1
        } else {
            openLocalUniStreams += 1
        }
    }

    /// Record closing a local stream.
    public mutating func recordLocalStreamClosed(bidirectional: Bool) {
        if bidirectional {
            if openLocalBidiStreams > 0 { openLocalBidiStreams -= 1 }
        } else {
            if openLocalUniStreams > 0 { openLocalUniStreams -= 1 }
        }
    }

    /// Check if peer can open a new stream.
    public func canAcceptRemoteStream(bidirectional: Bool) -> Bool {
        if bidirectional {
            return openRemoteBidiStreams < maxLocalBidiStreams
        } else {
            return openRemoteUniStreams < maxLocalUniStreams
        }
    }

    /// Record opening a remote stream.
    public mutating func recordRemoteStreamOpened(bidirectional: Bool) {
        if bidirectional {
            openRemoteBidiStreams += 1
        } else {
            openRemoteUniStreams += 1
        }
    }

    /// Record closing a remote stream.
    public mutating func recordRemoteStreamClosed(bidirectional: Bool) {
        if bidirectional {
            if openRemoteBidiStreams > 0 { openRemoteBidiStreams -= 1 }
        } else {
            if openRemoteUniStreams > 0 { openRemoteUniStreams -= 1 }
        }
    }

    /// Update remote stream limit (from peer's MAX_STREAMS).
    public mutating func updateRemoteStreamLimit(_ maxStreams: UInt64, bidirectional: Bool) {
        if bidirectional {
            if maxStreams > maxRemoteBidiStreams {
                maxRemoteBidiStreams = maxStreams
            }
        } else {
            if maxStreams > maxRemoteUniStreams {
                maxRemoteUniStreams = maxStreams
            }
        }
    }

    /// Generate MAX_STREAMS frame if needed.
    public mutating func generateMaxStreams(bidirectional: Bool) -> MaxStreamsFrame? {
        if bidirectional {
            guard maxLocalBidiStreams > 0 else { return nil }
            let threshold = maxLocalBidiStreams / 2
            if openRemoteBidiStreams >= threshold {
                let (newLimit, overflow) = maxLocalBidiStreams.addingReportingOverflow(10)
                maxLocalBidiStreams = overflow ? UInt64.max : newLimit
                return MaxStreamsFrame(maxStreams: maxLocalBidiStreams, isBidirectional: true)
            }
        } else {
            guard maxLocalUniStreams > 0 else { return nil }
            let threshold = maxLocalUniStreams / 2
            if openRemoteUniStreams >= threshold {
                let (newLimit, overflow) = maxLocalUniStreams.addingReportingOverflow(10)
                maxLocalUniStreams = overflow ? UInt64.max : newLimit
                return MaxStreamsFrame(maxStreams: maxLocalUniStreams, isBidirectional: false)
            }
        }
        return nil
    }

    /// Generate STREAMS_BLOCKED frame if blocked.
    public func generateStreamsBlocked(bidirectional: Bool) -> StreamsBlockedFrame? {
        if bidirectional {
            if openLocalBidiStreams >= maxRemoteBidiStreams {
                return StreamsBlockedFrame(streamLimit: maxRemoteBidiStreams, isBidirectional: true)
            }
        } else {
            if openLocalUniStreams >= maxRemoteUniStreams {
                return StreamsBlockedFrame(streamLimit: maxRemoteUniStreams, isBidirectional: false)
            }
        }
        return nil
    }
}
