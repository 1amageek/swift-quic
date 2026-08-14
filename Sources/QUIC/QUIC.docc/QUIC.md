# ``QUIC``

A Pure Swift QUIC session facade for Native, WASM, and Embedded Swift.

## Overview

The module binds the sans-I/O QUIC connection engine to caller-supplied
``NetworkingDatagram/DatagramTransport`` and ``NetworkingTime/AsyncTimer``
capabilities. TLS 1.3 handshake state is owned by `swift-tls`; cryptography and
PKI are owned by `swift-ssl`.

Use ``QUICClient`` for a client session and ``QUICServerConnection`` for one
accepted server session. Listener routing and connection-ID demultiplexing are
transport-adapter responsibilities.

The public drivers provide:

- TLS 1.3 authenticated connection establishment
- bidirectional and unidirectional QUIC streams
- QUIC datagrams
- connection close and peer event state
- loss-recovery and timer integration through an injected clock

Received datagrams remain owned by `OwnedBytes` and are borrowed only during a
synchronous engine transition. Engine-produced packet arrays transfer ownership
into the asynchronous send operation.

## Topics

### Sessions

- ``QUICClient``
- ``QUICServerConnection``
- ``QUICEngineConnection``

### Capabilities and errors

- ``QUICTLSCapabilityProviding``
- ``QUICConnectionDriverError``
