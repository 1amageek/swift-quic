# QUICCrypto/TLS Module

TLS 1.3 ハンドシェイク実装 (RFC 8446) と QUIC 統合 (RFC 9001)。

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            TLS13Handler                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────┐    ┌─────────────────────────────┐        │
│  │     ClientStateMachine      │    │     ServerStateMachine      │        │
│  │  - Start → Wait ServerHello │    │  - Start → Wait ClientHello │        │
│  │  - ServerHello → Handshake  │    │  - ClientHello → ServerHello│        │
│  │  - Finished → Connected     │    │  - Finished → Connected     │        │
│  └─────────────────────────────┘    └─────────────────────────────┘        │
│                   ↓                               ↓                          │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                          TLSOutput                                    │   │
│  │  - handshakeData(Data, level)                                        │   │
│  │  - keysAvailable(KeysAvailableInfo)  ← cipher suite を含む          │   │
│  │  - handshakeComplete(HandshakeCompleteInfo)                          │   │
│  │  - needMoreData                                                       │   │
│  │  - error(TLSError)                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Critical: KeysAvailableInfo に Cipher Suite を含める

**TLS で negotiation した cipher suite を KeysAvailableInfo に含めないと、
PacketProcessor が正しい暗号アルゴリズムを選択できない。**

### KeysAvailableInfo 構造

```swift
public struct KeysAvailableInfo: Sendable {
    public let level: EncryptionLevel
    public let clientSecret: SymmetricKey?
    public let serverSecret: SymmetricKey?
    public let cipherSuite: QUICCipherSuite  // ← 必須: negotiation 結果
}
```

### TLS13Handler での設定

```swift
// ServerStateMachine - ServerHello 送信時
outputs.append(.keysAvailable(KeysAvailableInfo(
    level: .handshake,
    clientSecret: clientSecret,
    serverSecret: serverSecret,
    cipherSuite: toQUICCipherSuite(state.context.cipherSuite)  // ← 必須
)))

// TLS CipherSuite → QUICCipherSuite 変換
private func toQUICCipherSuite(_ suite: CipherSuite) -> QUICCipherSuite {
    switch suite {
    case .tls_chacha20_poly1305_sha256:
        return .chacha20Poly1305Sha256
    case .tls_aes_256_gcm_sha384:
        return .aes128GcmSha256  // SHA-384 はハッシュのみ、鍵は AES-128
    default:
        return .aes128GcmSha256
    }
}
```

## PSK / Session Resumption

### Session Ticket Data Model

**重要**: `StoredSession` には `ticketNonce` を必ず含める。

```swift
public struct StoredSession: Sendable {
    public let resumptionMasterSecret: SymmetricKey
    public let cipherSuite: CipherSuite
    public let createdAt: Date
    public let lifetime: UInt32
    public let ticketAgeAdd: UInt32
    public let alpn: String?
    public let maxEarlyDataSize: UInt32
    public let ticketNonce: Data  // ← 必須: PSK derivation に必要
}
```

### PSK Flow

```
Server:
1. Handshake 完了後、NewSessionTicket を生成
2. ticket_nonce をランダム生成
3. StoredSession に ticket_nonce を保存
4. NewSessionTicket(ticket_nonce, ticket_lifetime, ...) を送信

Client (Resumption):
1. ClientHello に pre_shared_key extension を含める
2. binder を計算 (ticket_nonce から PSK を導出)

Server (Resumption Validation):
1. ticket_id から StoredSession を検索
2. session.ticketNonce を使って PSK を導出  ← placeholder を使わない
3. binder を検証
```

### Binder Hash Algorithm

**重要**: Binder hash は session の cipher suite に基づいて選択する。

```swift
// NG: 常に SHA-256
let transcriptHash = Data(SHA256.hash(data: truncatedTranscript))

// OK: cipher suite に基づいて選択
let transcriptHash: Data
switch session.cipherSuite {
case .tls_aes_256_gcm_sha384:
    transcriptHash = Data(SHA384.hash(data: truncatedTranscript))
default:
    transcriptHash = Data(SHA256.hash(data: truncatedTranscript))
}
```

## Key Schedule

```
                    PSK (or 0)
                       |
                       v
            +---> HKDF-Extract = Early Secret
            |
            +-----> Derive-Secret(., "ext binder" | "res binder", "")
            |                     = binder_key
            |
            +-----> Derive-Secret(., "c e traffic", ClientHello)
            |                     = client_early_traffic_secret
            |
      0 ----+
            |
            v
      +---> HKDF-Extract = Handshake Secret
      |
      +-----> Derive-Secret(., "c hs traffic", ClientHello...ServerHello)
      |                     = client_handshake_traffic_secret
      |
      +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello)
      |                     = server_handshake_traffic_secret
      |
      0 ----+
            |
            v
      +---> HKDF-Extract = Master Secret
      |
      +-----> Derive-Secret(., "c ap traffic", ClientHello...server Finished)
      |                     = client_application_traffic_secret_0
      |
      +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished)
      |                     = server_application_traffic_secret_0
      |
      +-----> Derive-Secret(., "res master", ClientHello...client Finished)
                            = resumption_master_secret
```

## Files

| ファイル | 責務 | RFC参照 |
|---------|------|--------|
| `TLS13Handler.swift` | Client/Server State Machine | RFC 8446 |
| `TLSOutput.swift` | TLS 処理結果の型定義 | - |
| `KeySchedule/TLSKeySchedule.swift` | TLS 1.3 Key Schedule | RFC 8446 Section 7 |
| `Session/SessionTicketStore.swift` | Session Ticket 管理 | RFC 8446 Section 4.6.1 |
| `Messages/*.swift` | TLS Message 型定義 | RFC 8446 Section 4 |
| `Extensions/*.swift` | TLS Extension 型定義 | RFC 8446 Section 4.2 |

## Testing

```bash
swift test --filter TLSTests
```

### テスト項目

- [ ] Full handshake (ECDHE)
- [ ] PSK resumption (0-RTT)
- [ ] ChaCha20-Poly1305 negotiation
- [ ] Certificate validation
- [ ] ALPN negotiation
