# swift-quic Context

QUIC プロトコル (RFC 9000, 9001, 9002) の Swift 実装。

## ディレクトリ構造

swift-quic は **Embedded-first**。プロトコルロジックは Embedded-clean な *core*
ターゲット（値型・呼び出し側ロック・sans-IO・crypto seam にジェネリック）に置き、
host (Foundation) モジュールはその上の薄いアダプタである。`Package.swift` の
`P2P_CORE_EMBEDDED=1` トグルで core を Embedded ビルドに切り替える（dual-build）。

```
Sources/
# --- Embedded-clean cores (dual-build: host + Embedded) ---
├── QUICWire/                 # Tier-3 ワイヤコーデック (Varint, Frame/, Packet/,
│                             #   Version, ProtocolLimits, SafeConversions, StandardFrameCodec)
├── QUICPacketProtectionCore/ # PacketProtector<C,A> / SuiteProtector<C> (`any` を置換), 鍵導出
├── QUICRecoveryCore/         # LossDetectorCore, RTTEstimatorCore, CUBIC/NewReno, Pacer
├── QUICStreamCore/           # Send/ReceiveStreamCore FSM, ReassemblyBuffer, FlowControllerCore
├── QUICTLSCore/              # TLS 1.3 鍵スケジュール + transcript hash + handshake FSM
├── QUICConnectionCore/       # DPLPMTUD, transport-params codec, packet parse/serialize core
# --- host adapters (Foundation) ---
├── QUICCore/                 # QUICWire+QUICConnectionCore の Foundation アダプタ
├── QUICCrypto/               # QUICTLSCore + QUICPacketProtectionCore のアダプタ (C = DefaultCryptoProvider)
├── QUICConnection/           # 接続状態管理 (QUICConnectionCore の上)
├── QUICRecovery/             # ロス検出、輻輳制御 (QUICRecoveryCore の上)
├── QUICStream/               # ストリーム管理 (QUICStreamCore の上)
├── QUICTransport/            # UDP 統合 (swift-nio-udp)
└── QUIC/                     # 高レベル API (host orchestrator — まだ core 化されていない)
```

`QUIC`, `QUICConnection`, `QUICCrypto`, `QUICCrypto/TLS`, `QUICRecovery`,
`QUICStream` には個別の `CONTEXT.md` がある。6 つの core ターゲットには専用の
`CONTEXT.md` はなく、対応する親アダプタの `CONTEXT.md` で説明する。

> **状態 (重要)**: Embedded コンパイルは core を対象とし、接続ファサード全体は
> まだ対象外。host orchestrator (`QUICEndpoint` ~1280L / `ManagedConnection`
> ~2257L / `TimerManager` ~329L) は未だ cored engine に移植されていない（"M11"
> 待ち）。リリース済み `1.3.0` は host API。core は `embedded` ブランチで未リリース
> （"M8" 待ち）。高レベル API（`QUICEndpoint.serve/dial`,
> `QUICConfiguration.production`, `MockTLSProvider`）は不変かつ正確。

---

## コードレビュー結果（履歴）

> **注意**: 以下は **2026-01-19 の Codex CLI レビュー時点のスナップショット**で
> あり、現在の `embedded` ブランチには当てはまらない。当時 "未対応" だった項目は
> その後対応済み。最新の設計・対応状況は `PHASE_B_DESIGN.md`（#1/#7/#8 の根本対応）
> および git 履歴を参照すること。下表は履歴として残す。

| # | 問題 | 重要度 | 当時の状態 | 現状 |
|---|------|--------|-----------|------|
| 1 | ACK レンジ DoS (`LossDetector`) | Warning | 未対応 | 対応済み — `PHASE_B_DESIGN.md` (bounded iteration) + その後の硬化。ロジックは `QUICRecoveryCore.LossDetectorCore` に core 化 |
| 2 | ChaCha20 エンディアン | Warning | 対応済み | 対応済み |
| 3 | X.509 検証不足 (EKU/SAN/NameConstraints) | Warning | 未対応 | 対応済み — `QUICCrypto/TLS/X509/X509Validator.swift` で EKU(serverAuth)/SAN/NameConstraints を検証 |
| 4 | MAX_STREAMS ゼロガード | Warning | 対応済み | 対応済み |
| 5 | MockTLSProvider デフォルト | Warning | 未対応 | 対応済み — TLS プロバイダは必須（insecure default なし）。`.production`/`.development`/`.testing` で明示注入 |
| 6 | AES HP 非 Apple | Warning | 未対応 | 解消 — HP は `DefaultCryptoProvider` / `QUICPacketProtectionCore` の seam 経由（host swift-crypto / Embedded BoringSSL）。CommonCrypto 直叩きではない |
| 7 | ヘッダ検証未使用 | Info | 未対応 | `PHASE_B_DESIGN.md` 参照 |
| 8 | STREAM オーバーヘッド誤差 | Info | 未対応 | `PHASE_B_DESIGN.md` 参照 |
| 9 | peekBytes コメント | Info | 問題なし | 問題なし |

crypto は `DefaultCryptoProvider`（host swift-crypto / Embedded BoringSSL）に統一
され、削除された per-lib `QUICFoundationProvider` を置き換えた。

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
