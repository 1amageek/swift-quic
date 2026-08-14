// QUICRecoveryCore
//
// The Embedded-clean loss-recovery core for QUIC (RFC 9002, RFC 9438):
//   - Congestion controllers as value types: `NewRenoCore` (RFC 9002 §7) and
//     `CubicCore` (RFC 9438), each a `struct` with `mutating`
//     onPacketSent/onPacketsAcknowledged/onPacketsLost/onECNCongestionEvent/
//     onPersistentCongestion methods and stored cwnd/ssthresh/recovery-state fields.
//   - The token-bucket pacer as a value type: `PacerCore` (RFC 9002 §7.7),
//     preserving the 1.3.0 `Double`→`UInt64` overflow fix (headroom clamp +
//     `.isFinite` guard + rate>0 guard).
//   - The RTT estimator as a value type: `RTTEstimatorCore` (RFC 9002 §5), EWMA
//     smoothed RTT / variance / min / latest in nanoseconds, with a pure
//     `probeTimeoutNanos` (RFC 9002 §6.2.1 PTO).
//   - The loss detector as a value type: `LossDetectorCore` (RFC 9002 §6), packet-
//     threshold + time-threshold detection over a sorted `SentPacketView` array,
//     `mutating onAckReceived`/`detectLostPackets` returning newly-acked / lost views
//     and the loss-timer deadline as `UInt64` nanos.
//   - Anti-amplification as a value type: `AntiAmplificationCore` (RFC 9000 §8.1),
//     saturating byte counters.
//   - Supporting value types: `CongestionCoreState`, `RTTSnapshot`,
//     `CongestionPacket`, `SentPacketView`, `AckInterval`, `CongestionCoreConstants`.
//
// Caller-locked + clock-seam pattern: every type here is a pure value type with
// `mutating` methods. There is NO Synchronization.Mutex, NO actor, NO
// ContinuousClock/Date, and NO Foundation. Time is INJECTED as a monotonic
// `UInt64` nanosecond parameter (`nowNanos` / `timeSentNanos`); emitted deadlines
// (`nextSendNanos`, recovery start, `lossTimeNanos`, PTO) are returned as `UInt64`
// values. The caller owns synchronization and the clock.
//
// Packet-number-space orchestration and timer scheduling live in
// `QUICConnectionEngineCore`. The public driver supplies monotonic time through
// `NetworkingTime` and performs suspension outside engine isolation.
