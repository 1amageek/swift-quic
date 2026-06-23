/// QUIC Stream State Machine value types (RFC 9000 Section 3)
///
/// The send-side and receive-side state enums plus the stored FSM accounting for
/// a single stream, expressed as Embedded-clean value types. The byte buffers and
/// reassembly logic live in `SendStreamCore` / `ReceiveStreamCore`; this file holds
/// only the lifecycle states and the per-stream offset / flow-control / final-size
/// accounting that those cores drive.
///
/// Embedded-clean: no Foundation, no `any`, no `Mutex`, no `ContinuousClock`.

// MARK: - Stream State Enums

/// Send-side stream state (RFC 9000 Section 3.1).
public enum SendState: Sendable, Hashable {
    case ready
    case send
    case dataSent
    case dataRecvd
    case resetSent
    case resetRecvd
}

/// Receive-side stream state (RFC 9000 Section 3.2).
public enum RecvState: Sendable, Hashable {
    case recv
    case sizeKnown
    case dataRecvd
    case dataRead
    case resetRecvd
    case resetRead
}

// MARK: - Stream State

/// State for a single QUIC stream (FSM + offset / flow-control accounting).
public struct StreamState: Sendable {
    /// Stream ID.
    public let id: UInt64

    /// Send state (for outgoing data).
    public var sendState: SendState

    /// Receive state (for incoming data).
    public var recvState: RecvState

    /// Send offset (next byte to send).
    public var sendOffset: UInt64

    /// Receive offset (next byte expected / highest byte received).
    public var recvOffset: UInt64

    /// Send flow control limit.
    public var sendMaxData: UInt64

    /// Receive flow control limit.
    public var recvMaxData: UInt64

    /// Whether FIN has been sent.
    public var finSent: Bool

    /// Whether FIN has been received.
    public var finReceived: Bool

    /// Final size (if known).
    public var finalSize: UInt64?

    /// Creates a new stream state.
    public init(
        id: UInt64,
        initialSendMaxData: UInt64,
        initialRecvMaxData: UInt64
    ) {
        self.id = id
        self.sendState = .ready
        self.recvState = .recv
        self.sendOffset = 0
        self.recvOffset = 0
        self.sendMaxData = initialSendMaxData
        self.recvMaxData = initialRecvMaxData
        self.finSent = false
        self.finReceived = false
        self.finalSize = nil
    }

    /// Whether this stream is bidirectional.
    public var isBidirectional: Bool {
        StreamID.isBidirectional(id)
    }

    /// Whether this stream is unidirectional.
    public var isUnidirectional: Bool {
        StreamID.isUnidirectional(id)
    }

    /// Whether this stream can send data.
    public var canSend: Bool {
        switch sendState {
        case .ready, .send:
            return true
        default:
            return false
        }
    }

    /// Whether this stream can receive data.
    public var canReceive: Bool {
        switch recvState {
        case .recv, .sizeKnown:
            return true
        default:
            return false
        }
    }

    /// Available send capacity.
    public var sendCapacity: UInt64 {
        guard sendMaxData > sendOffset else { return 0 }
        return sendMaxData - sendOffset
    }
}
