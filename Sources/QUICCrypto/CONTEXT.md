# QUICCrypto Module

RFC 9001 準拠の QUIC パケット暗号化実装。

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              QUICCrypto                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        TLS Layer                                      │   │
│  │  TLS13Handler → KeysAvailableInfo → (secrets + cipher suite)         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Key Derivation Layer                               │   │
│  │  KeyMaterial.derive(secret, cipherSuite) → (key, iv, hp)             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                    ↓                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                    Packet Protection Layer                            │   │
│  │  KeyMaterial.createCrypto() → (PacketOpener, PacketSealer)           │   │
│  │                                                                        │   │
│  │  ┌─────────────────────┐    ┌─────────────────────┐                  │   │
│  │  │   AES-128-GCM       │    │  ChaCha20-Poly1305  │                  │   │
│  │  │   - Opener          │    │   - Opener          │                  │   │
│  │  │   - Sealer          │    │   - Sealer          │                  │   │
│  │  │   - HeaderProtection│    │   - HeaderProtection│                  │   │
│  │  └─────────────────────┘    └─────────────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Critical: Cipher Suite Flow

**TLS で negotiation した cipher suite は必ず packet protection まで伝播させる必要がある。**

### 正しいフロー

```
TLS13Handler (ServerHello/ClientHello)
    ↓ cipher suite negotiation
    ↓
KeysAvailableInfo(level, clientSecret, serverSecret, cipherSuite: QUICCipherSuite)
    ↓
PacketProcessor.installKeys(info, isClient)
    ↓
KeyMaterial.derive(from: secret, cipherSuite: info.cipherSuite)  ← 必ず cipherSuite を渡す
    ↓
keyMaterial.createCrypto()  ← ファクトリメソッドが正しい型を選択
    ↓
AES128GCMOpener/Sealer または ChaCha20Poly1305Opener/Sealer
```

### NG パターン（過去のバグ）

```swift
// NG: cipher suite を無視して AES にデフォルト
let keys = try KeyMaterial.derive(from: secret)  // ← cipherSuite 引数なし
let opener = try AES128GCMOpener(keyMaterial: keys)  // ← ハードコード

// OK: cipher suite を伝播
let keys = try KeyMaterial.derive(from: secret, cipherSuite: info.cipherSuite)
let (opener, sealer) = try keys.createCrypto()  // ← ファクトリが正しい型を選択
```

## Cipher Suite Support

| Cipher Suite | Key Length | IV Length | HP Key Length | Hash |
|-------------|-----------|-----------|---------------|------|
| AES-128-GCM-SHA256 | 16 bytes | 12 bytes | 16 bytes | SHA-256 |
| ChaCha20-Poly1305-SHA256 | 32 bytes | 12 bytes | 32 bytes | SHA-256 |

## Header Protection

### AES Header Protection (RFC 9001 Section 5.4.3)

```
sample = packet[pn_offset+4 : pn_offset+20]  // 16 bytes
mask = AES-ECB(hp_key, sample)[0:5]          // 5 bytes
```

### ChaCha20 Header Protection (RFC 9001 Section 5.4.4)

**重要**: ChaCha20 Header Protection は counter を使用する。

```
sample = packet[pn_offset+4 : pn_offset+20]  // 16 bytes
counter = sample[0:4]                         // 4 bytes, little-endian
nonce = sample[4:16]                          // 12 bytes
mask = ChaCha20(hp_key, counter, nonce)[0:5]  // 5 bytes
```

**Swift Crypto の制限**: `ChaChaPoly` は AEAD であり、raw ChaCha20 with counter を公開していない。
そのため `chaCha20Block()` 関数を RFC 8439 Section 2.3 に基づいて実装している。

```swift
// ChaCha20Block.swift
func chaCha20Block(key: Data, counter: UInt32, nonce: Data) -> Data
```

## Key Derivation (HKDF-Expand-Label)

RFC 8446 Section 7.1 に準拠:

```
HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

HkdfLabel = struct {
    uint16 length = Length;
    opaque label<7..255> = "tls13 " + Label;
    opaque context<0..255> = Context;
}
```

QUIC 固有のラベル:
- `"quic key"` - パケット保護鍵
- `"quic iv"` - パケット保護 IV
- `"quic hp"` - ヘッダー保護鍵

## Files

| ファイル | 責務 | RFC参照 |
|---------|------|--------|
| `AEAD.swift` | AES/ChaCha20 Opener/Sealer 実装 | RFC 9001 Section 5 |
| `ChaCha20Block.swift` | ChaCha20 Block Function (Header Protection 用) | RFC 8439 Section 2.3 |
| `InitialSecrets.swift` | Initial 鍵導出, KeyMaterial, QUICCipherSuite | RFC 9001 Section 5.2 |
| `CryptoState.swift` | CryptoContext, HeaderProtection protocol | RFC 9001 Section 5 |

## Testing

```bash
swift test --filter QUICCryptoTests
```

### テストベクター

RFC 9001 Appendix A に記載のテストベクターを使用:
- A.1: Initial Keys (Client/Server)
- A.2: Handshake Keys
- A.5: ChaCha20-Poly1305 Short Header Packet
