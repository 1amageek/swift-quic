# swift-quic Context

QUIC プロトコル (RFC 9000, 9001, 9002) の Swift 実装。

## ディレクトリ構造

```
Sources/
├── QUICCore/       # コア型、パケット/フレームコーデック
├── QUICCrypto/     # 暗号化操作、TLS 1.3
├── QUICConnection/ # 接続状態管理
├── QUICRecovery/   # ロス検出、輻輳制御
├── QUICStream/     # ストリーム管理
└── QUIC/           # 高レベル API
```

各ディレクトリには個別の `CONTEXT.md` があります。

---

## コードレビュー結果

**レビュー日**: 2026-01-19
**ツール**: OpenAI Codex CLI (gpt-5.2-codex)

### Critical (重大) - なし

### Warning (警告) - 6件

#### 1. ACK レンジによる CPU DoS

**ファイル**: `Sources/QUICRecovery/LossDetector.swift:144-188`

**問題**: `processAckedRanges` が ACK レンジ内の全パケット番号をイテレート。悪意ある巨大レンジで O(range) ループを強制可能。

**対策案**: `sentPackets` のキーをイテレートし、レンジ内に含まれるか確認する方式に変更。

```swift
// Before: O(range_length) - 危険
for pn in checkStart...current {
    if let packet = state.sentPackets[pn] { ... }
}

// After: O(sentPackets.count * log(ranges)) - 安全
for pn in state.sentPackets.keys {
    if isInAckRanges(pn, ranges: ackFrame.ackRanges) { ... }
}
```

---

#### 2. ChaCha20 カウンタロードのエンディアン問題

**ファイル**: `Sources/QUICCrypto/AEAD.swift:427-433`

**問題**: `load(as: UInt32.self)` がネイティブエンディアンを仮定。ビッグエンディアン環境で誤動作の可能性。

**対策案**: リトルエンディアンで明示的にデコード。

```swift
// Before: エンディアン依存
let counter = sample.withUnsafeBytes { $0.load(as: UInt32.self) }

// After: 明示的リトルエンディアン
let counter = sample.withUnsafeBytes {
    UInt32(littleEndian: $0.loadUnaligned(as: UInt32.self))
}
```

---

#### 3. X.509 検証の不足

**ファイル**: `Sources/QUICCrypto/TLS/X509/X509Validator.swift:172-223`

**問題**: EKU (serverAuth)、SAN 要件、名前制約の検証なし。不正な証明書を受け入れる可能性。

**対策案**:
- ExtendedKeyUsage で serverAuth を検証
- Subject Alternative Name (SAN) のホスト名検証
- 名前制約の強制

---

#### 4. MAX_STREAMS 自動拡張の問題

**ファイル**: `Sources/QUICStream/FlowController.swift:423-438`

**問題**: `maxLocalStreams = 0` の場合も自動拡張が発動し、ストリーム禁止設定を上書き。

**対策案**: ゼロ値チェックを追加。

```swift
// Before: ゼロでも拡張される
let threshold = maxLocalBidiStreams / 2
if openRemoteBidiStreams >= threshold { ... }

// After: ゼロなら拡張しない
guard maxLocalBidiStreams > 0 else { return nil }
let threshold = maxLocalBidiStreams / 2
if openRemoteBidiStreams >= threshold { ... }
```

---

#### 5. MockTLSProvider のデフォルト使用

**ファイル**: `Sources/QUIC/QUICEndpoint.swift:174-180`

**問題**: TLS プロバイダ未指定時に `MockTLSProvider` を使用。本番環境で TLS が無効化される危険性。

**対策案**:
- 本番ビルドで MockTLSProvider の使用を禁止
- または TLS プロバイダを必須パラメータに変更

---

#### 6. AES ヘッダ保護の非 Apple プラットフォーム問題

**ファイル**: `Sources/QUICCrypto/AEAD.swift:439-485`

**問題**: Linux 等で AES-ECB ヘッダ保護が例外を投げる。

**対策案**: OpenSSL/BoringSSL または ソフトウェアフォールバックを実装。

---

### Info (情報) - 3件

#### 1. ヘッダ検証の未使用

**ファイル**: `Sources/QUICCore/Packet/PacketHeader.swift:560-619`

**問題**: `LongHeader.validate()` / `ShortHeader.validate()` が定義されているがデコードパスで呼ばれていない。

**対策案**: ヘッダ保護除去後に検証を呼び出す。

---

#### 2. STREAM フレームオーバーヘッドの近似誤差

**ファイル**: `Sources/QUICStream/StreamManager.swift:491-498`

**問題**: 固定 11 バイトで計算しているが varint サイズで変動。パケットサイズ超過の可能性。

**対策案**: 実際の varint サイズを計算してオーバーヘッドを算出。

---

#### 3. `peekBytes` のコメント不一致

**ファイル**: `Sources/QUICCore/DataReader.swift:71-79`

**問題**: "no copy" とコメントしているが `Data(data[position..<])` でコピーが発生。

**対策案**: コメントを修正、または実際にコピーを回避する実装に変更。

---

## 対応状況

| # | 問題 | 重要度 | 状態 |
|---|------|--------|------|
| 1 | ACK レンジ DoS | Warning | 未対応 |
| 2 | ChaCha20 エンディアン | Warning | ✅ 対応済み (Phase 11) |
| 3 | X.509 検証不足 | Warning | 未対応 |
| 4 | MAX_STREAMS ガード | Warning | ✅ 対応済み (Phase 11) |
| 5 | MockTLSProvider デフォルト | Warning | 未対応 |
| 6 | AES HP 非 Apple | Warning | 未対応 |
| 7 | ヘッダ検証未使用 | Info | 未対応 |
| 8 | STREAM オーバーヘッド | Info | 未対応 |
| 9 | peekBytes コメント | Info | ✅ 問題なし (コメントは正確) |

---

## セキュリティ強化履歴

### Phase 11 (2026-01-19) - 完了

- `SafeConversions.swift` - 安全な整数変換ユーティリティ
- `ProtocolLimits.swift` - RFC 準拠のプロトコル制限値
- `ConnectionID` - throwing イニシャライザに変更
- `NewConnectionIDFrame` - throwing イニシャライザに変更
- `FrameCodec` / `PacketCodec` - 安全な変換を適用
- 全テストファイルを新 API に対応

---

## テスト

```bash
# 通常のテスト
swift test --filter QUICCoreTests
swift test --filter QUICCryptoTests
swift test --filter QUICTests

# ベンチマーク（分離済み）
swift test --filter QUICBenchmarks
```

---

## 参考

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) - QUIC Transport Protocol
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) - Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) - QUIC Loss Detection and Congestion Control
