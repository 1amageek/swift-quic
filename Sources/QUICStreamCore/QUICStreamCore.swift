// QUICStreamCore
//
// The Embedded-clean QUIC STREAM state machine (RFC 9000 §2–4):
//   - Send-stream FSM as a value type: `SendStreamCore` (Ready → Send → DataSent →
//     DataRecvd, plus ResetSent / ResetRecvd), a `struct` with `mutating`
//     write/finish/generateFrames/handleStopSending/generateResetStream/
//     acknowledgeData/acknowledgeReset methods and stored sendOffset / sendMaxData /
//     finSent / send-buffer state. STREAM / RESET_STREAM frames are the `[UInt8]`-based
//     codec types from `QUICWire`.
//   - Receive-stream FSM as a value type: `ReceiveStreamCore` (Recv → SizeKnown →
//     DataRecvd → DataRead, plus ResetRecvd) with an in-order reassembly buffer,
//     `mutating` receive/read/updateRecvMaxData/handleResetStream and a pure
//     generateStopSending. Preserves the RFC 9000 §4.5 final-size and §4.1 flow-control
//     SECURITY validations exactly (FINAL_SIZE_ERROR / FLOW_CONTROL_ERROR are thrown,
//     never clamped).
//   - The reassembly buffer as a value type: `StreamReassemblyBuffer`, out-of-order
//     range insertion + overlap merge + contiguous read over `[UInt8]`, with the
//     final-offset bound (2^62-1) and buffer-overflow checks intact.
//   - Per-stream + connection flow control as a value type: `FlowControllerCore`
//     (window updates, blocked detection, MAX_STREAMS / STREAMS_BLOCKED accounting),
//     preserving STREAM_LIMIT_ERROR-relevant stream-concurrency limits.
//   - Supporting value types: `StreamState`, `SendState`, `RecvState`, `StreamID`, and
//     the typed errors `StreamError` / `DataBufferError`.
//
// Caller-locked + clock-seam pattern: every type here is a pure value type with
// `mutating` methods. There is NO Synchronization.Mutex, NO actor, NO
// ContinuousClock/Date, and NO Foundation. Byte payloads are `[UInt8]`. The caller
// owns synchronization and any clock.
//
// NOT in this target (host-only, see the QUICStream adapter): the caller-locked
// `DataStream` (the `final class` that wraps `SendStreamCore` + `ReceiveStreamCore`
// under one `Mutex`, bridges `Data` ⇄ `[UInt8]`, and synthesizes the unified
// `StreamState`), the `DataBuffer` / `FlowController` `Data`-facing wrappers, the
// `StreamManager` (`Mutex`-held stream multiplexer), the `StreamScheduler`, and any
// async delivery (`AsyncStream` / continuations) which stays adapter-side.
