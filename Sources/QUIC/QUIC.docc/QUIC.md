# ``QUIC``

A pure Swift implementation of the QUIC protocol (RFC 9000).

## Overview

swift-quic provides a modern, async/await-based QUIC implementation for Swift applications. It is designed primarily for libp2p integration but can be used as a standalone QUIC library.

QUIC is a multiplexed transport protocol built on UDP that provides:
- Encrypted connections by default (TLS 1.3)
- Multiplexed streams over a single connection
- Low-latency connection establishment
- Connection migration support
- Improved congestion control

### Key Features

- **async/await everywhere** - Modern Swift concurrency
- **Value types first** - Struct-based data types
- **Protocol-oriented** - Clean abstractions
- **Sendable compliance** - Thread-safe by design

## Getting Started

### Client Connection

```swift
let config = QUICConfiguration.production {
    MyTLSProvider()
}
let endpoint = QUICEndpoint(configuration: config)
let connection = try await endpoint.connect(to: serverAddress)
let stream = try await connection.openStream()
try await stream.write(data)
let response = try await stream.read()
```

### Server Listener

```swift
let config = QUICConfiguration.production {
    MyTLSProvider()
}
let endpoint = try await QUICEndpoint.listen(
    address: bindAddress,
    configuration: config
)
for await connection in endpoint.incomingConnections {
    Task {
        for await stream in connection.incomingStreams {
            // Handle stream
        }
    }
}
```

## Topics

### Essentials

- ``QUICEndpoint``
- ``QUICConfiguration``
- ``QUICSecurityMode``

### Connections

- ``QUICConnectionProtocol``
- ``SocketAddress``

### Streams

- ``QUICStreamProtocol``

### Errors

- ``QUICSecurityError``
