# QUICConnectionEngineCore context

`QUICConnectionEngineCore` owns the per-connection, sans-I/O QUIC state
machine. It drives the packet, recovery, stream, flow-control, idle-timeout, and
path-validation cores without owning a socket, clock, TLS session, or lock.

## Boundary

```text
QUIC public driver (Mutex, datagram I/O, timer, TLS)
                         |
                         v
            QUICConnectionEngine
                         |
       +-----------------+-----------------+
       |                 |                 |
   packet core       recovery core      stream core
```

- The engine is a value type. The public driver is the caller that locks.
- `nowNanos` is supplied to state transitions; the engine never sleeps and does
  not read a platform clock.
- Incoming datagrams use a scoped `Span` borrow. The borrow is synchronous and
  does not escape.
- Outbound packets are final `[UInt8]` owners returned to the driver.
- TLS authentication and capability resolution are owned by `swift-tls`; this
  engine only consumes handshake bytes, transport parameters, traffic secrets,
  and the authenticated completion transition.
- Packet protection is the closed `SuiteProtector` composition from
  `QUICPacketProtectionCore`; no alternative crypto backend is selected here.

## Failure contract

- Malformed input, missing keys, flow-control violations, final-size
  violations, transport-parameter violations, and packet-number exhaustion
  throw `QUICEngineError`.
- A per-packet authentication failure is dropped where RFC 9001 permits it; it
  does not terminate an otherwise valid connection.
- Idle expiry is reported in timer output. The driver owns transport shutdown.
- Missing capabilities never produce placeholder output or success.

## Protocol invariants

- Initial secrets are derived from the original destination connection ID.
- Encryption levels and packet-number spaces remain distinct.
- ACK ranges are bounded by locally known sent packets.
- PTO queues an acknowledgement-eliciting probe and uses bounded backoff.
- Anti-amplification is enforced until the server path is validated.
- Key update advances both secret generation and key phase atomically within
  one caller-locked transition.
- A short-header packet terminates a coalesced datagram.

## Portable contract

Native, WASM, and Embedded compile the same engine source. The core has no
Foundation, NIO, socket I/O, clock access, or shared mutable state. Portable
validation uses the matching Swift 6.4 toolchain and SDK, with
`SWIFT_NETWORKING_EMBEDDED=1` enabling Embedded mode.
