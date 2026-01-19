# QUIC Module

QUIC Endpoint と Packet Processing の統合層。

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                             QUICEndpoint                                      │
│                        (Server/Client Endpoint)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          run(socket:)                                 │   │
│  │                                                                        │   │
│  │    withTaskGroup {                                                    │   │
│  │        ├── packetReceiveLoop()   ← socket.incomingPackets             │   │
│  │        └── timerProcessingLoop() ← loss detection, PTO               │   │
│  │    }                                                                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        PacketProcessor                                │   │
│  │  - installKeys(KeysAvailableInfo, isClient)                          │   │
│  │  - encryptPacket() / decryptPacket()                                 │   │
│  │  - CryptoContext per EncryptionLevel                                 │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Critical: I/O Loop Lifecycle

### 問題のあるパターン（過去のバグ）

```swift
// NG: AsyncStream が finish されないと for await が永久にブロック
public func run(socket: any QUICSocket) async throws {
    await withTaskGroup(of: Void.self) { group in
        group.addTask {
            for await packet in socket.incomingPackets {  // ← ここでブロック
                guard !shouldStop else { break }
                // ...
            }
        }
        // ...
    }
}

public func stop() async {
    shouldStop = true
    ioTask?.cancel()  // ← ioTask は nil、意味がない
}
```

### 正しいパターン

```swift
// OK: withTaskCancellationHandler で socket を停止
public func run(socket: any QUICSocket) async throws {
    try await withTaskCancellationHandler {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.packetReceiveLoop(socket: socket) }
            group.addTask { await self.timerProcessingLoop(socket: socket) }
            await group.waitForAll()
        }
    } onCancel: {
        Task { await socket.stop() }
    }
}

public func stop() async {
    shouldStop = true
    // socket.stop() で AsyncStream が finish される
    if let socket = socket {
        await socket.stop()
    }
}
```

### Socket 側の要件

```swift
// QUICSocket 実装は stop() で continuation を finish する必要がある
public func stop() async {
    await transport.stop()
    incomingContinuation.finish()  // ← 必須: これがないと for await が終了しない
}
```

## Critical: Key Installation

**PacketProcessor.installKeys() は cipher suite を正しく伝播する必要がある。**

### 正しいパターン

```swift
public func installKeys(_ info: KeysAvailableInfo, isClient: Bool) throws {
    let cipherSuite = info.cipherSuite  // ← KeysAvailableInfo から取得

    // 0-RTT (単方向)
    if info.level == .zeroRTT {
        let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
        let (opener, sealer) = try clientKeys.createCrypto()  // ← ファクトリ使用
        // ...
        return
    }

    // 双方向鍵
    let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
    let serverKeys = try KeyMaterial.derive(from: serverSecret, cipherSuite: cipherSuite)

    let readKeys = isClient ? serverKeys : clientKeys
    let writeKeys = isClient ? clientKeys : serverKeys

    // ファクトリメソッドで正しい型を生成
    let (opener, _) = try readKeys.createCrypto()
    let (_, sealer) = try writeKeys.createCrypto()

    let context = CryptoContext(opener: opener, sealer: sealer)
    installContext(context, for: info.level)
}
```

### NG パターン（過去のバグ）

```swift
// NG: cipher suite を無視して AES をハードコード
let clientKeys = try KeyMaterial.derive(from: clientSecret)  // ← cipherSuite なし
let opener = try AES128GCMOpener(keyMaterial: readKeys)      // ← ハードコード
let sealer = try AES128GCMSealer(keyMaterial: writeKeys)     // ← ハードコード
```

## Packet Flow

### Inbound (Decryption)

```
UDP Datagram
    ↓
CoalescedPacketParser.parse()   ← 複数パケットを分離
    ↓
PacketProcessor.decryptPacket()
    ├── extractHeaderInfo()     ← DCID, packet type 取得
    ├── context(for: level)     ← 暗号化レベルの CryptoContext 取得
    ├── opener.removeHeaderProtection()
    └── opener.open()           ← AEAD 復号
    ↓
ParsedPacket(header, packetNumber, frames)
```

### Outbound (Encryption)

```
Frames + Header
    ↓
PacketProcessor.encryptLongHeaderPacket() or encryptShortHeaderPacket()
    ├── context(for: level)     ← CryptoContext 取得
    ├── sealer.seal()           ← AEAD 暗号化
    └── sealer.applyHeaderProtection()
    ↓
Encrypted Packet Data
```

## Encryption Levels

| Level | Usage | Packet Type |
|-------|-------|-------------|
| Initial | Connection establishment | Initial |
| ZeroRTT | Early data (client only) | 0-RTT |
| Handshake | Handshake messages | Handshake |
| Application | Application data | 1-RTT (Short Header) |

## Files

| ファイル | 責務 |
|---------|------|
| `QUICEndpoint.swift` | Server/Client Endpoint, I/O Loop |
| `PacketProcessor.swift` | Packet 暗号化/復号, 鍵管理 |
| `PacketEncoder.swift` | Packet → Wire Format |
| `PacketDecoder.swift` | Wire Format → Packet |
| `CoalescedPacketParser.swift` | UDP Datagram 内の複数パケット分離 |
| `UDPSocket.swift` | NIO UDP Transport |

## Testing

```bash
swift test --filter QUICTests
```

### 重要なテスト項目

- [ ] Endpoint start/stop lifecycle
- [ ] ChaCha20-Poly1305 packet encryption/decryption
- [ ] Coalesced packet handling
- [ ] Key update (1-RTT key rotation)
