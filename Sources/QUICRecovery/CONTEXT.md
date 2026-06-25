# QUICRecovery — CONTEXT
Scope/role: the host (Foundation) loss-detection and congestion-control adapter (RFC 9002); thin layer over the `QUICRecoveryCore` value types.
Last reviewed: 2026-06-25

Invariants and design intent the source does not state structurally. Read this
before changing loss detection, ACK processing, or congestion control. The
detection / congestion logic lives in the Embedded-clean `QUICRecoveryCore` value
types; the host adapters here hold them under `Mutex` and bridge `Data` / clock
time. Time enters the cores as a monotonic `UInt64` nanosecond parameter — there
is no `ContinuousClock` in a core.

## Contracts (the load-bearing rules)

- **The detection / CC logic lives in the core.** `LossDetectorCore` (sorted-array
  packet/time threshold detection), `RTTEstimatorCore` (smoothing + min-RTT),
  `CubicCore` (RFC 9438) / `NewRenoCore` (RFC 9002 §7), `PacerCore` (token-bucket
  pacing, RFC 9002 §7.7), `AntiAmplificationCore` (server 3× limit). The host
  wrappers (`LossDetector`, `RTTEstimator`, `NewRenoCongestionController`,
  `CubicCongestionController`, `AntiAmplificationLimiter`) hold these under `Mutex`.
  `AckManager` and `SentPacket` remain host-side.

## Invariants (must hold; tests guard them)

- **ACK processing is DoS-bounded.** The detector never iterates an
  attacker-controlled range. It iterates the locally-known sent packets and tests
  membership against the ACK ranges (`O(sentPackets × ranges)`), instead of
  iterating `largest...checkStart` (`O(Σ range_length)`, attacker-controlled). Do
  not reintroduce a loop over an untrusted range. ACK ranges are capped (256) and
  gap/length arithmetic is underflow-checked.
- **Loss detection follows RFC 9002 §6:** packet-threshold (3 newer packets
  acked) OR time-threshold (`max(latest, smoothed RTT) × 9/8`, floored at the
  timer granularity); PTO with exponential backoff.
- **Anti-amplification (RFC 9000 §8.1):** a server sends at most 3× the bytes it
  received before address validation, using saturating multiplication/addition so
  byte tracking never overflows; `canSend` refuses when the arithmetic would
  overflow.
- **Congestion control (RFC 9002 §7):** slow start, congestion avoidance (AIMD),
  fast recovery, persistent-congestion detection, ECN-CE response, with pacing.

## Embedded constraints (do not regress)

- `QUICRecoveryCore` stays Embedded-clean: no Foundation, no `any`, no `Mutex`, no
  `ContinuousClock`. Time is injected as `nowNanos: UInt64`. Keep the host clock
  bridging in the adapters only.

## Build

- Host: `swift build` / `swift test --filter QUICRecoveryTests`. Performance
  numbers and how to run benchmarks live in the README `## Performance` section.
