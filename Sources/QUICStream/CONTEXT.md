# QUICStream — CONTEXT
Scope/role: the host (Foundation) stream multiplexing + flow-control adapter (RFC 9000 §2–4); thin layer over the `QUICStreamCore` value types.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing the stream FSMs, reassembly, or flow control. The stream
state-machine logic lives in the Embedded-clean `QUICStreamCore` value types over
`[UInt8]`; the adapters here (`DataStream`, `FlowController`, `DataBuffer`) hold
those cores under a `Mutex` and bridge `Data`. `StreamManager` and the priority
scheduler (`StreamScheduler`) are host-only orchestration.

## Contracts (the load-bearing rules)

- **The stream FSMs live in the core.** `SendStreamCore` / `ReceiveStreamCore`
  (send/receive FSMs, RFC 9000 §3), `StreamReassemblyBuffer` (out-of-order
  reassembly), `FlowControllerCore` (connection + stream-level flow control). Fixes
  to stream behaviour belong there.
- **Retransmission is NOT this module's responsibility.** `generateStreamFrames`
  consumes the send buffer, so a `DataStream` cannot retransmit on its own. The
  generated frames must be handed to `QUICRecovery`, which tracks sent frames and
  drives retransmission on loss. Do not add retransmission state here.
- **Stream ID assignment is bit-encoded (RFC 9000 §2.1):** bit 0 = initiator
  (0 client / 1 server), bit 1 = directionality (0 bidi / 1 uni).

## Invariants (must hold; tests guard them)

- **Final-size immutability (RFC 9000 §4.5).** A RESET_STREAM final size is
  validated against advertised flow-control limits; a final size set by FIN is
  reconciled against already-buffered out-of-order data (data beyond the final
  size that arrived earlier is detected, not silently kept).
- **Flow-control violations are connection-fatal (RFC 9000 §4):** a peer exceeding
  the advertised connection or stream data limit is a FLOW_CONTROL_ERROR.
- **Reassembly overflow counts only genuinely new bytes.** Overlapping/duplicate
  segments do not inflate the buffered-byte count — overflow is judged on
  non-overlapping bytes actually added, not on raw `data.count`. (A regression here
  produced false overflow errors on duplicate data.)
- **A stream-ID mismatch throws, it does not crash.** `DataStream.receive` throws
  `StreamError.streamIDMismatch` rather than `fatalError` when the frame's stream
  ID does not match the stream — it signals a dispatcher bug but must stay
  recoverable.
- **Priority scheduling (RFC 9218):** urgency 0–7 (0 highest, default 3) with an
  incremental flag; high-urgency streams are served first, with round-robin fair
  queuing within an urgency level (persistent cursors prevent starvation of peers
  at the same level).

## Embedded constraints (do not regress)

- `QUICStreamCore` stays Embedded-clean: no Foundation, no `any`, no `Mutex`. Keep
  the `Mutex`/`Data` bridging in the adapters only.

## Build

- Host: `swift build` / `swift test --filter QUICStreamTests`.
