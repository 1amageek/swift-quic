// QUICStreamSet.swift
// The engine's stream multiplexing state: per-stream send/receive FSMs plus the
// connection-level flow controller, driving the existing `QUICStreamCore` value
// types. Embedded-clean: no Mutex, no Foundation. The engine calls in under the
// facade's lock.

import QUICWire
import QUICStreamCore

/// All open streams plus connection-level flow control.
struct QUICStreamSet: Sendable {
    /// Send FSMs keyed by stream ID.
    var sendStreams: [UInt64: SendStreamCore] = [:]
    /// Receive FSMs keyed by stream ID.
    var receiveStreams: [UInt64: ReceiveStreamCore] = [:]
    /// Connection-level flow control + stream-count limits.
    var flowController: FlowControllerCore

    /// Whether this endpoint is the client (determines stream-ID parity).
    let isClient: Bool

    /// The next local bidirectional stream index to allocate.
    private var nextLocalBidiIndex: UInt64 = 0
    /// The next local unidirectional stream index to allocate.
    private var nextLocalUniIndex: UInt64 = 0

    /// Per-stream initial receive limit for bidi-local streams.
    let initialMaxStreamDataBidiLocal: UInt64
    /// Per-stream initial receive limit for bidi-remote streams.
    let initialMaxStreamDataBidiRemote: UInt64
    /// Per-stream initial receive limit for uni streams.
    let initialMaxStreamDataUni: UInt64
    /// The peer's per-stream send limit (set from peer transport params).
    var peerInitialMaxStreamDataBidiLocal: UInt64
    var peerInitialMaxStreamDataBidiRemote: UInt64
    var peerInitialMaxStreamDataUni: UInt64
    /// Reassembly buffer cap for receive streams.
    let maxBufferSize: UInt64

    init(
        isClient: Bool,
        flowController: FlowControllerCore,
        initialMaxStreamDataBidiLocal: UInt64,
        initialMaxStreamDataBidiRemote: UInt64,
        initialMaxStreamDataUni: UInt64,
        peerInitialMaxStreamDataBidiLocal: UInt64,
        peerInitialMaxStreamDataBidiRemote: UInt64,
        peerInitialMaxStreamDataUni: UInt64,
        maxBufferSize: UInt64
    ) {
        self.isClient = isClient
        self.flowController = flowController
        self.initialMaxStreamDataBidiLocal = initialMaxStreamDataBidiLocal
        self.initialMaxStreamDataBidiRemote = initialMaxStreamDataBidiRemote
        self.initialMaxStreamDataUni = initialMaxStreamDataUni
        self.peerInitialMaxStreamDataBidiLocal = peerInitialMaxStreamDataBidiLocal
        self.peerInitialMaxStreamDataBidiRemote = peerInitialMaxStreamDataBidiRemote
        self.peerInitialMaxStreamDataUni = peerInitialMaxStreamDataUni
        self.maxBufferSize = maxBufferSize
    }

    // MARK: - Local stream creation

    /// Opens a local stream and returns its ID, enforcing the peer's stream-count
    /// limit (RFC 9000 §4.6). Throws a typed error if blocked.
    mutating func openLocal(bidirectional: Bool) throws(QUICEngineError) -> UInt64 {
        guard flowController.canOpenStream(bidirectional: bidirectional) else {
            throw .flowControl("peer stream limit reached")
        }
        let index = bidirectional ? nextLocalBidiIndex : nextLocalUniIndex
        let id = StreamID.make(index: index, isClient: isClient, isBidirectional: bidirectional)
        if bidirectional { nextLocalBidiIndex += 1 } else { nextLocalUniIndex += 1 }

        let sendLimit = bidirectional ? peerInitialMaxStreamDataBidiLocal : peerInitialMaxStreamDataUni
        sendStreams[id] = SendStreamCore(id: id, isLocallyInitiated: true, initialSendMaxData: sendLimit)
        if bidirectional {
            let recvLimit = initialMaxStreamDataBidiLocal
            receiveStreams[id] = ReceiveStreamCore(
                id: id, isLocallyInitiated: true, initialRecvMaxData: recvLimit, maxBufferSize: maxBufferSize)
            flowController.initializeStream(id)
        }
        flowController.recordLocalStreamOpened(bidirectional: bidirectional)
        return id
    }

    // MARK: - Remote stream discovery

    /// Ensures FSMs exist for a peer-initiated stream referenced by ID. Returns
    /// `true` if this call created a new stream (so the engine surfaces it).
    mutating func ensureRemoteStream(_ id: UInt64) -> Bool {
        // A stream is remote-initiated if its parity does not match ours.
        let isRemote = StreamID.isClientInitiated(id) != isClient
        guard isRemote else {
            // Locally-initiated: it must already exist (peer is referencing our stream).
            return false
        }
        if receiveStreams[id] != nil || sendStreams[id] != nil { return false }

        let bidirectional = StreamID.isBidirectional(id)
        let recvLimit = bidirectional ? initialMaxStreamDataBidiRemote : initialMaxStreamDataUni
        receiveStreams[id] = ReceiveStreamCore(
            id: id, isLocallyInitiated: false, initialRecvMaxData: recvLimit, maxBufferSize: maxBufferSize)
        flowController.initializeStream(id)
        if bidirectional {
            let sendLimit = peerInitialMaxStreamDataBidiRemote
            sendStreams[id] = SendStreamCore(id: id, isLocallyInitiated: false, initialSendMaxData: sendLimit)
        }
        flowController.recordRemoteStreamOpened(bidirectional: bidirectional)
        return true
    }
}
