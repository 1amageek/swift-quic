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
| `StreamPriority.swift` | RFC 9218 priority parameters (urgency, incremental) |
| `StreamScheduler.swift` | Priority-based scheduling with fair queuing |

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
    // Open a new local stream with optional priority
    public func openStream(bidirectional: Bool, priority: StreamPriority = .default) throws -> UInt64

    // Receive STREAM frame (creates stream if needed)
    public func receive(frame: StreamFrame) throws

    // Generate frames for all streams (priority-ordered)
    public func generateStreamFrames(maxBytes: Int) -> [StreamFrame]

    // Priority management
    public func setPriority(_ priority: StreamPriority, for streamID: UInt64) throws
    public func priority(for streamID: UInt64) throws -> StreamPriority

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

### StreamPriority

RFC 9218-aligned priority parameters.

```swift
public struct StreamPriority: Sendable, Hashable, Comparable {
    public let urgency: UInt8      // 0-7 (0 = highest)
    public let incremental: Bool

    public static let highest = StreamPriority(urgency: 0, incremental: false)
    public static let `default` = StreamPriority(urgency: 3, incremental: false)
    public static let lowest = StreamPriority(urgency: 7, incremental: false)
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

// Open stream with priority
let criticalID = try manager.openStream(bidirectional: true, priority: .highest)
let normalID = try manager.openStream(bidirectional: true)  // Default priority
let backgroundID = try manager.openStream(bidirectional: true, priority: .lowest)

// Write data
try manager.write(streamID: criticalID, data: criticalPayload)
try manager.write(streamID: normalID, data: normalPayload)
try manager.write(streamID: backgroundID, data: backgroundPayload)

// Generate frames - high priority streams served first
let frames = manager.generateStreamFrames(maxBytes: 1200)

// Adjust priority dynamically
try manager.setPriority(.high, for: backgroundID)

// Process received frames
try manager.receive(frame: incomingStreamFrame)

// Read received data
if let data = manager.read(streamID: remoteStreamID) {
    // Process data
}
```

## Priority Scheduling (RFC 9218)

### Overview

RFC 9000 recommends implementations provide a way for applications to indicate stream priorities.
This module implements RFC 9218 (HTTP/3 Extensible Priority Scheme) parameters.

### Priority Parameters

| Parameter | Range | Default | Description |
|-----------|-------|---------|-------------|
| `urgency` | 0-7 | 3 | Lower = higher priority |
| `incremental` | bool | false | Supports progressive delivery |

### Scheduling Algorithm

```
1. Group streams by urgency level (0-7)
2. Process groups in priority order (0 first)
3. Within same priority: round-robin for fairness
4. Cursors persist between calls
```

### Example

```
Streams: A(u=0), B(u=0), C(u=3), D(u=7)

Call 1: [A, B, C, D] - cursor for u=0 advances
Call 2: [B, A, C, D] - round-robin within u=0
```

### Starvation Prevention

High priority streams are served first, but if they exhaust their data/window,
lower priority streams get bandwidth. The `incremental` flag (future) enables
more aggressive interleaving.

## Testing

```bash
swift test --filter QUICStreamTests
```

159 tests covering:
- DataStream state machine
- StreamManager multiplexing
- FlowController limits
- DataBuffer reassembly
- Edge cases and error handling
- **RFC 9000 Section 4.5 compliance** (Final Size)
- **RFC 9218 Priority Scheduling** (StreamPriority, StreamScheduler)

### RFC準拠テスト

テストはRFC 9000の仕様に基づいて記述されている。各テストはRFCセクション番号を含み、
対応する仕様要件をdocコメントで引用している。

```swift
/// RFC 9000 Section 4.5:
/// "A receiver MUST close the connection with error FLOW_CONTROL_ERROR
/// if a sender violates the advertised connection or stream data limits"
@Test("RFC 9000 4.5: RESET_STREAM with final size exceeding flow control limit throws error")
func resetStreamExceedsFlowControlLimit() throws { ... }
```

**カバーされているRFCセクション**:
- Section 2.1: Stream ID Assignment
- Section 3: Stream States
- Section 3.5: STOP_SENDING / RESET_STREAM
- Section 4: Flow Control
- Section 4.5: Stream Final Size

## 設計上の注意点

### 再送バッファについて

`DataStream.generateStreamFrames()` は送信バッファを消費してフレームを生成する。
ACK受信前にバッファが空になるため、DataStream単体では再送できない。

**設計意図**:
- 再送はQUICRecoveryモジュールの責務
- `LossDetector`が送信済みフレームを追跡
- パケットロス検出時にRecoveryモジュールが再送を制御

**使用時の注意**:
- `generateStreamFrames()`の戻り値フレームはRecoveryモジュールに渡すこと
- StreamManager単体での再送は未サポート

### DataBufferのオーバーフロー検出

重複・オーバーラップするセグメントがある場合、実際に追加されるバイト数のみをカウントする。

```swift
// 例: 90バイトのバッファに20バイトの完全重複データを挿入
// → 実際の新規バイト = 0、オーバーフローにならない
let actualNewBytes = calculateNonOverlappingBytes(offset, data)
```

**経緯**: Codexレビューで検出。マージ前に`data.count`でオーバーフロー判定していたため、
重複データで誤ったオーバーフローエラーが発生していた。

### FIN受信時の既存バッファ検証

FIN受信時に`finalSize`を設定する前に、既存のバッファセグメントが`finalSize`を超えていないか検証する。

**経緯**: out-of-orderでFINより後のデータが先に到着した場合、
FIN設定後にそのデータが`finalSize`を超えていることを検出できなかった。

```
問題シナリオ:
1. offset=100, length=50 受信 → バッファに格納
2. offset=50, FIN=true 受信 → finalSize=50
3. バッファ内の100-150は検出されない ← 修正済み
```

### streamIDミスマッチのエラーハンドリング

`DataStream.receive()`でフレームの`streamID`がストリームの`id`と一致しない場合、
`fatalError`ではなく`StreamError.streamIDMismatch`をthrowする。

**経緯**: Codexレビューで指摘。fatalErrorはプロセス全体をクラッシュさせるため、
回復可能なエラーとして扱うべき。これはStreamManagerのディスパッチロジックのバグを示す。
