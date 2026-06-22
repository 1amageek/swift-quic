// QUICRecoveryCore
//
// The Embedded-clean congestion-control + pacing core for QUIC loss recovery
// (RFC 9002 §7, RFC 9438):
//   - Congestion controllers as value types: `NewRenoCore` (RFC 9002 §7) and
//     `CubicCore` (RFC 9438), each a `struct` with `mutating`
//     onPacketSent/onPacketsAcknowledged/onPacketsLost/onECNCongestionEvent/
//     onPersistentCongestion methods and stored cwnd/ssthresh/recovery-state fields.
//   - The token-bucket pacer as a value type: `PacerCore` (RFC 9002 §7.7),
//     preserving the 1.3.0 `Double`→`UInt64` overflow fix (headroom clamp +
//     `.isFinite` guard + rate>0 guard).
//   - Supporting value types: `CongestionCoreState`, `RTTSnapshot`,
//     `CongestionPacket`, `CongestionCoreConstants`.
//
// Caller-locked + clock-seam pattern: every type here is a pure value type with
// `mutating` methods. There is NO Synchronization.Mutex, NO actor, NO
// ContinuousClock/Date, and NO Foundation. Time is INJECTED as a monotonic
// `UInt64` nanosecond parameter (`nowNanos` / `timeSentNanos`); emitted deadlines
// (`nextSendNanos`, recovery start) are returned as `UInt64` values. The caller
// owns synchronization and the clock.
//
// NOT in this target (host-only, see the QUICRecovery adapter): the caller-locked
// holders (`NewRenoCongestionController`, `CubicCongestionController`, `Pacer`) that
// wrap these value types in a `Mutex`, read the host `ContinuousClock`, convert
// `Instant`/`Duration` to/from nanoseconds, and project `SentPacket`/`RTTEstimator`
// into `CongestionPacket`/`RTTSnapshot`; the `CongestionController` protocol and
// `CongestionControlAlgorithm` factory; and the loss/RTT/ack machinery (LossDetector,
// RTTEstimator, AckManager, PacketNumberSpaceManager) which still use
// `ContinuousClock.Instant`/`Duration` and the QUICCore `AckFrame` host-side.
