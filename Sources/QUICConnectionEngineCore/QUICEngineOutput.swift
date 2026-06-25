// QUICEngineOutput.swift
// The value-type result of a sans-IO engine step (`receive` / `flush` /
// `handleTimeout`). It is pure data: the host facade performs the actual UDP
// sends and async-stream yields. Embedded-clean: no Foundation, no `any`.

import QUICWire

/// What a single ``QUICConnectionEngine`` step produced.
///
/// The engine is sans-IO: instead of touching a socket, it returns the datagrams
/// the facade must send and the events the facade must surface (new streams,
/// readable stream data, handshake completion, peer close). Every datagram is a
/// fully protected, ready-to-send `[UInt8]` paid out in send order.
public struct QUICEngineOutput: Sendable {
    /// Fully protected datagrams to send to the peer, in order.
    public var datagramsToSend: [[UInt8]]

    /// CRYPTO-stream bytes the peer delivered, grouped by encryption level, that
    /// the facade must feed to its (async) TLS provider. The engine itself does
    /// not run the async handshake — it reassembles ordered CRYPTO data and hands
    /// it out so the host TLS seam (or a future cored handshake driver) consumes
    /// it. Empty once the handshake is complete.
    public var handshakeData: [HandshakeChunk]

    /// Stream IDs newly opened by the peer in this step (to be surfaced on the
    /// facade's `incomingStreams`).
    public var newStreams: [UInt64]

    /// Stream IDs that became readable in this step (so the facade can wake any
    /// pending `read()` continuations). The actual bytes are drained via
    /// ``QUICConnectionEngine/readStream(_:)``.
    public var readableStreams: [UInt64]

    /// DATAGRAM-frame payloads (RFC 9221) delivered by the peer in this step.
    public var datagrams: [[UInt8]]

    /// `true` when the handshake completed in this step.
    public var handshakeComplete: Bool

    /// `true` when the peer closed (CONNECTION_CLOSE) in this step.
    public var peerClosed: Bool

    /// A peer CONNECTION_CLOSE reason, if one arrived in this step.
    public var closeReason: ConnectionCloseInfo?

    public init(
        datagramsToSend: [[UInt8]] = [],
        handshakeData: [HandshakeChunk] = [],
        newStreams: [UInt64] = [],
        readableStreams: [UInt64] = [],
        datagrams: [[UInt8]] = [],
        handshakeComplete: Bool = false,
        peerClosed: Bool = false,
        closeReason: ConnectionCloseInfo? = nil
    ) {
        self.datagramsToSend = datagramsToSend
        self.handshakeData = handshakeData
        self.newStreams = newStreams
        self.readableStreams = readableStreams
        self.datagrams = datagrams
        self.handshakeComplete = handshakeComplete
        self.peerClosed = peerClosed
        self.closeReason = closeReason
    }

    /// Whether this output carries nothing for the facade to act on.
    public var isEmpty: Bool {
        datagramsToSend.isEmpty && handshakeData.isEmpty && newStreams.isEmpty
            && readableStreams.isEmpty && datagrams.isEmpty
            && !handshakeComplete && !peerClosed && closeReason == nil
    }
}

/// Ordered CRYPTO-stream bytes at one encryption level (RFC 9001 §4).
public struct HandshakeChunk: Sendable, Equatable {
    public var level: EncryptionLevel
    public var data: [UInt8]

    public init(level: EncryptionLevel, data: [UInt8]) {
        self.level = level
        self.data = data
    }
}

/// A peer-sent CONNECTION_CLOSE summary (RFC 9000 §19.19).
public struct ConnectionCloseInfo: Sendable, Equatable {
    public var errorCode: UInt64
    public var isApplicationError: Bool
    public var frameType: UInt64?
    public var reasonPhrase: [UInt8]

    public init(
        errorCode: UInt64,
        isApplicationError: Bool,
        frameType: UInt64?,
        reasonPhrase: [UInt8]
    ) {
        self.errorCode = errorCode
        self.isApplicationError = isApplicationError
        self.frameType = frameType
        self.reasonPhrase = reasonPhrase
    }
}
