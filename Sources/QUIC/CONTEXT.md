# QUIC source context

This target is the public, transport-independent QUIC session facade. It owns
TLS 1.3 handshake orchestration around the sans-I/O `QUICConnectionEngine` and
drives that engine through capabilities supplied by the embedder.

## Public roles

- `QUICClient` owns one client TLS session and one engine-backed connection.
- `QUICServerConnection` owns one accepted server TLS session and one
  engine-backed connection. Listener routing and connection-ID demultiplexing
  remain transport responsibilities.
- `QUICEngineConnection` owns the receive and timer loops and exposes stream,
  datagram, connection-close, and peer-event operations.
- `QUICTLSCapabilityProviding` resolves signature, certificate, and key-exchange
  operations requested by the TLS state machine.

There is no legacy endpoint facade or fallback implementation in this target.

## Dependency and ownership boundary

```text
NetworkingDatagram + NetworkingTime
                 |
                 v
        QUICEngineConnection
                 |
        QUICConnectionEngineCore
                 |
                 v
       QUICClient / QUICServerConnection
                 |
              QUICTLS
                 |
            swift-ssl
```

- `NetworkingCore` owns `OwnedBytes`, `Span` borrowing, and IP endpoints.
- `NetworkingDatagram` owns the asynchronous datagram contract.
- `NetworkingTime` owns the monotonic clock and sleep contract.
- QUIC targets own QUIC varints, packet framing, recovery, transport parameters,
  stream state, and connection state.
- `swift-tls` owns TLS 1.3 and QUIC-TLS state transitions.
- `swift-ssl` owns cryptographic primitives, ASN.1, X.509, and TLS mechanisms.

## Data path

```text
transport.receive()
    -> InboundDatagram owns OwnedBytes
    -> scoped Span borrow
    -> QUICConnectionEngine.receive
    -> engine emits owned [UInt8] datagrams
    -> consume Array storage into OwnedBytes
    -> transport.send(OwnedBytes)
```

The receive parser borrows the datagram only during the synchronous engine
step. The pointer never escapes the borrow closure or crosses an `await`.
Outbound arrays are consumed into `OwnedBytes`; do not replace that transfer
with `OwnedBytes(copying:)` on the packet loop.

## Concurrency and failure contracts

- Native, WASM, and Embedded use the same `Synchronization.Mutex` storage and
  mutation entries. Platform branches must not replace a mutex with raw state.
- Engine and TLS state are mutated only inside their mutex closures.
- I/O, timer sleep, TLS capability calls, and external callbacks execute after
  the corresponding mutex is released.
- `run()` is single-use. A second call fails with a typed invalid-state error.
- Datagram I/O, time, TLS, and engine failures remain distinguishable through
  `QUICConnectionDriverError`; they are never converted to a successful close.
- A clean transport close is represented by `receive() == nil`.
- Timer waiters are terminated on loop exit so cancellation cannot leave a
  suspended continuation behind.
- Peer authentication is fail-closed. Missing or rejected TLS capabilities
  terminate the handshake.

## Verification

- Native behavior tests run with `xcodebuild test`.
- Throughput benchmarks are opt-in through `SWIFT_QUIC_ENABLE_BENCHMARKS=1` and
  remain outside the default test graph.
- WASM and Embedded validation compile, link, and run the opt-in
  `quic-wasm-validation` executable with the pinned Swift 6.4 toolchain and
  matching SDKs. The same source-level ownership and synchronization contracts
  apply on every target.
