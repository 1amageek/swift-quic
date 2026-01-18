# QUICStream Module

> Stream management and flow control for QUIC (RFC 9000 Section 2-4)

## Overview

This module implements QUIC stream multiplexing and flow control. It handles:
- Individual stream state machines (send/receive)
- Stream creation and lifecycle management
- Connection and stream-level flow control
- Out-of-order data reassembly

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  StreamManager                                               │
│  (Stream multiplexing, creation, frame generation)          │
├─────────────────────────────────────────────────────────────┤
│  DataStream                                                  │
│  (Individual stream: send buffer, receive buffer, state)    │
├─────────────────────────────────────────────────────────────┤
│  FlowController              │  DataBuffer                   │
│  (Flow control limits)       │  (Out-of-order reassembly)   │
└─────────────────────────────────────────────────────────────┘
```

## Files

| File | Purpose |
|------|---------|
| `DataStream.swift` | Individual stream with send/receive state machines |
| `StreamManager.swift` | Stream multiplexing, creation, lifecycle, frame handling |
| `FlowController.swift` | Connection and stream-level flow control |
| `DataBuffer.swift` | Out-of-order data reassembly with FIN tracking |
| `StreamState.swift` | Send/receive state enums per RFC 9000 |

## Key Types

### DataStream

Class representing an individual QUIC stream. Thread-safe via `Mutex<T>`.

```swift
public final class DataStream: Sendable {
    // Write data to send buffer
    public func write(_ data: Data) throws

    // Read contiguous data from receive buffer
    public func read() -> Data?

    // Generate STREAM frames for transmission
    public func generateStreamFrames(maxBytes: Int, connectionWindow: UInt64) -> [StreamFrame]

    // Process received STREAM frame
    public func receive(_ frame: StreamFrame) throws

    // Handle STOP_SENDING from peer
    public func handleStopSending(errorCode: UInt64)

    // Generate RESET_STREAM frame
    public func generateResetStream(errorCode: UInt64) -> ResetStreamFrame?
}
```

### StreamManager

Manages all streams for a connection. Thread-safe via `Mutex<T>`.

```swift
public final class StreamManager: Sendable {
    // Open a new local stream
    public func openStream(bidirectional: Bool) throws -> UInt64

    // Receive STREAM frame (creates stream if needed)
    public func receive(frame: StreamFrame) throws

    // Generate frames for all streams
    public func generateStreamFrames(maxBytes: Int) -> [StreamFrame]

    // Handle flow control frames
    public func handleMaxStreamData(_ frame: MaxStreamDataFrame)
    public func handleMaxData(_ frame: MaxDataFrame)
    public func handleStopSending(_ frame: StopSendingFrame)
    public func handleResetStream(_ frame: ResetStreamFrame) throws

    // Cleanup
    public func closeStream(id streamID: UInt64)
    public func closeAllStreams(errorCode: UInt64?) -> [ResetStreamFrame]
}
```

### FlowController

Tracks flow control limits and generates flow control frames.

```swift
public struct FlowController: Sendable {
    // Connection-level limits
    public func canReceive(bytes: UInt64) -> Bool
    public func canSend(bytes: UInt64) -> Bool
    public mutating func generateMaxData() -> MaxDataFrame?

    // Stream-level limits
    public func canReceiveOnStream(_ streamID: UInt64, endOffset: UInt64) -> Bool
    public mutating func generateMaxStreamData(for streamID: UInt64) -> MaxStreamDataFrame?

    // Stream concurrency
    public func canOpenStream(bidirectional: Bool) -> Bool
    public mutating func generateMaxStreams(bidirectional: Bool) -> MaxStreamsFrame?
}
```

### DataBuffer

Ordered buffer for reassembling out-of-order stream data.

```swift
public struct DataBuffer: Sendable {
    // Insert data (handles out-of-order, overlapping segments)
    public mutating func insert(offset: UInt64, data: Data, fin: Bool) throws

    // Read contiguous data from current position
    public mutating func readContiguous() -> Data?

    // Check completion state
    public var isComplete: Bool { get }
}
```

## Stream ID Assignment (RFC 9000 Section 2.1)

```
Stream ID bits: [.... .... .... ..TI]
  - I (bit 0): 0 = client-initiated, 1 = server-initiated
  - T (bit 1): 0 = bidirectional, 1 = unidirectional

Client bidi:  0, 4, 8, 12, ...
Server bidi:  1, 5, 9, 13, ...
Client uni:   2, 6, 10, 14, ...
Server uni:   3, 7, 11, 15, ...
```

## Stream States (RFC 9000 Section 3)

### Send State Machine

```
        o
        | Create Stream
        v
    +-------+
    | Ready | Send STREAM / STREAM_DATA_BLOCKED
    +-------+
        |
        | Send STREAM
        v
    +-------+
    | Send  | Send STREAM / STREAM_DATA_BLOCKED
    +-------+
        |
        | Send STREAM + FIN
        v
    +----------+
    | DataSent | Receive all ACKs
    +----------+
        |
        v
    +----------+
    | DataRecvd| (Terminal)
    +----------+

Alternative: Send RESET_STREAM → ResetSent → ResetRecvd
```

### Receive State Machine

```
        o
        | Receive STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
        v
    +-------+
    | Recv  | Receive STREAM
    +-------+
        |
        | Receive STREAM + FIN
        v
    +-----------+
    | SizeKnown | Receive STREAM
    +-----------+
        |
        | All data received
        v
    +----------+
    | DataRecvd| Read by application
    +----------+
        |
        v
    +----------+
    | DataRead | (Terminal)
    +----------+

Alternative: Receive RESET_STREAM → ResetRecvd → ResetRead
```

## Flow Control (RFC 9000 Section 4)

### Connection Level

- `MAX_DATA`: Advertised by receiver, limits total bytes across all streams
- `DATA_BLOCKED`: Sent when blocked by connection limit

### Stream Level

- `MAX_STREAM_DATA`: Advertised by receiver, limits bytes on single stream
- `STREAM_DATA_BLOCKED`: Sent when blocked by stream limit

### Stream Concurrency

- `MAX_STREAMS`: Limits concurrent streams by type (bidi/uni)
- `STREAMS_BLOCKED`: Sent when blocked by stream count limit

## Thread Safety

All types use `Synchronization.Mutex<T>` for internal state:

```swift
public final class DataStream: Sendable {
    private let _internal: Mutex<DataStreamInternalState>
}
```

This allows safe concurrent access without actors.

## Usage Example

```swift
// Create manager
let manager = StreamManager(
    isClient: true,
    initialMaxData: 1_000_000,
    initialMaxStreamDataBidiLocal: 100_000,
    peerInitialMaxStreamDataBidiLocal: 100_000,
    peerInitialMaxStreamsBidi: 100
)

// Open stream and write
let streamID = try manager.openStream(bidirectional: true)
try manager.write(streamID: streamID, data: payload)
try manager.finish(streamID: streamID)

// Generate frames for transmission
let frames = manager.generateStreamFrames(maxBytes: 1200)

// Process received frames
try manager.receive(frame: incomingStreamFrame)

// Read received data
if let data = manager.read(streamID: remoteStreamID) {
    // Process data
}
```

## Testing

```bash
swift test --filter QUICStreamTests
```

106 tests covering:
- DataStream state machine
- StreamManager multiplexing
- FlowController limits
- DataBuffer reassembly
- Edge cases and error handling
