# QUICConnection Module

QUIC Connection ハンドラと状態管理。

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         QUICConnectionHandler                                 │
│                    (Per-Connection State Machine)                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Connection State                               │   │
│  │                                                                        │   │
│  │  ┌─────────┐   ┌───────────┐   ┌───────────┐   ┌──────────┐         │   │
│  │  │ Initial │ → │ Handshake │ → │ Connected │ → │  Closed  │         │   │
│  │  └─────────┘   └───────────┘   └───────────┘   └──────────┘         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        Key Management                                 │   │
│  │                                                                        │   │
│  │  TLSOutput.keysAvailable(KeysAvailableInfo)                          │   │
│  │        ↓                                                               │   │
│  │  installKeys(info, role)                                              │   │
│  │        ↓                                                               │   │
│  │  CryptoContext per EncryptionLevel                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Critical: Key Installation

**QUICConnectionHandler.installKeys() も cipher suite を正しく伝播する必要がある。**

PacketProcessor と同様のパターンを適用する。

### 正しいパターン

```swift
private func installKeys(_ info: KeysAvailableInfo, role: ConnectionRole) throws {
    let cipherSuite = info.cipherSuite  // ← KeysAvailableInfo から取得

    // 0-RTT handling
    if info.level == .zeroRTT {
        let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
        let (opener, sealer) = try clientKeys.createCrypto()
        // ...
        return
    }

    // Standard bidirectional keys
    let clientKeys = try KeyMaterial.derive(from: clientSecret, cipherSuite: cipherSuite)
    let serverKeys = try KeyMaterial.derive(from: serverSecret, cipherSuite: cipherSuite)

    let readKeys: KeyMaterial
    let writeKeys: KeyMaterial
    if role == .client {
        readKeys = serverKeys
        writeKeys = clientKeys
    } else {
        readKeys = clientKeys
        writeKeys = serverKeys
    }

    // ファクトリメソッドで正しい型を生成（AES or ChaCha20）
    let (opener, _) = try readKeys.createCrypto()
    let (_, sealer) = try writeKeys.createCrypto()

    // CryptoContext に設定
    // ...
}
```

### NG パターン（過去のバグ）

```swift
// NG: cipher suite を無視して AES をハードコード
let readKeys = try KeyMaterial.derive(from: serverSecret)   // ← cipherSuite なし
let writeKeys = try KeyMaterial.derive(from: clientSecret)  // ← cipherSuite なし

let opener = try AES128GCMOpener(keyMaterial: readKeys)     // ← ハードコード
let sealer = try AES128GCMSealer(keyMaterial: writeKeys)    // ← ハードコード
```

## TLS Integration Flow

```
QUICConnectionHandler
    │
    ├── processIncomingPacket()
    │       ↓
    │   TLSProvider.handleMessage()
    │       ↓
    │   TLSOutput (multiple outputs possible)
    │       │
    │       ├── .handshakeData(data, level)
    │       │       → 送信キューに追加
    │       │
    │       ├── .keysAvailable(info)
    │       │       → installKeys(info, role)  ← cipher suite を伝播
    │       │
    │       ├── .handshakeComplete(info)
    │       │       → state = .connected
    │       │
    │       └── .error(error)
    │               → connection close
    │
    └── processOutgoingPacket()
            ↓
        CryptoContext.sealer.seal()
```

## Connection Role

```swift
public enum ConnectionRole: Sendable {
    case client
    case server
}
```

- **Client**: 接続を開始、Initial パケットを送信
- **Server**: 接続を受け入れ、Initial パケットに応答

## Files

| ファイル | 責務 |
|---------|------|
| `QUICConnectionHandler.swift` | Connection 状態管理, TLS 統合 |
| `ConnectionState.swift` | Connection 状態定義 |
| `ConnectionID.swift` | Connection ID 管理 |

## Testing

```bash
swift test --filter QUICConnectionTests
```

### 重要なテスト項目

- [ ] Full handshake (client + server)
- [ ] ChaCha20-Poly1305 cipher suite
- [ ] 0-RTT data handling
- [ ] Connection migration
- [ ] Key update
