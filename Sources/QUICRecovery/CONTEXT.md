# QUICRecovery Module

RFC 9002 準拠の Loss Detection と Congestion Control 実装。

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  PacketNumberSpaceManager                                        │
│  (3つの暗号化レベルを統合管理)                                    │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │  LossDetector   │  │   AckManager    │  │  RTTEstimator   │  │
│  │ (ロス検出)      │  │ (ACK生成)       │  │ (RTT推定)       │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│  CongestionController (Protocol)                                 │
│  └── NewRenoCongestionController (実装)                          │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Characteristics

### Bottleneck Analysis (2026-01 Profiling)

**真のボトルネック**: `Dictionary<UInt64, SentPacket>` の insert/remove サイクル

| 操作 | 性能 | 備考 |
|------|------|------|
| Mutex lock/unlock | 132M ops/sec | ボトルネックではない |
| Dictionary insert | 1.6M ops/sec | 単純挿入 |
| Dictionary insert+remove | **15.5K cycles/sec** | ACK処理パターン（ボトルネック） |
| LossDetector.onPacketSent | 1.47M ops/sec | ≈ Dictionary insert 限界 |
| ACK処理 | 14-16K ack/sec | ≈ Dict insert+remove 限界 |

### 性能階層マップ

```
超高速 (>100M ops/sec)
├── Mutex lock/unlock:     132.69M ops/sec
├── Array append (cap):    239.87M ops/sec
└── Duration subtraction:  180.20M ops/sec

高速 (10M-100M ops/sec)
├── Dictionary lookup:     59.24M ops/sec
├── Dictionary iteration:  50.10M elements/sec
└── ContinuousClock.now:   37.49M ops/sec

中速 (1M-10M ops/sec)
├── Dictionary insert:     1.60M ops/sec
├── SentPacket in Dict:    1.55M ops/sec
└── LossDetector.onPacketSent: 1.47M ops/sec

ボトルネック (<100K ops/sec)
├── Dict insert+remove:    15.56K cycles/sec  ← 真のボトルネック
└── LossDetector ACK処理:  14-16K ack/sec
```

### Design Decisions

#### 1. Mutex vs Atomic

**採用**: `class + Mutex<T>`

- Mutex は 132M ops/sec で十分高速
- Atomic Counter は追加のメモリバリアオーバーヘッドあり
- 状態更新はバッチで行われるため、Mutex の方が効率的

#### 2. Dictionary vs OrderedDictionary

**採用**: 標準 `Dictionary`

- OrderedDictionary は定数係数が大きい
- 典型的な QUIC 接続では <1000 パケットが in-flight
- 小規模データでは標準 Dictionary の方が高速

#### 3. 初期容量の設定

**採用**: `Dictionary(minimumCapacity: 128)`

- rehash を削減
- 10% 程度の性能改善

### Optimization History

- 2026-01: プロファイリング実施
  - 真のボトルネック特定: Dictionary insert/remove サイクル
  - Mutex は問題ではないことを確認
  - Dictionary 初期容量最適化を実施

### Optimization Results (2026-01)

| 測定項目 | 最適化前 | 最適化後 | 改善率 |
|---------|---------|---------|--------|
| Send phase | 1.16M pkt/sec | 8.40M pkt/sec | **7.2x** |
| ACK (no loss) | 13.83K ack/sec | 42.95K ack/sec | **3.1x** |
| ACK (with loss) | 15.86K ack/sec | 46.47K ack/sec | **2.9x** |

**実施した変更:**
1. `LossState.sentPackets` に `Dictionary(minimumCapacity: 128)` を設定
2. `ackedPackets` の `reserveCapacity` を ACK ranges から推定

### Future Improvements

より根本的な改善が必要な場合:

- **Slab Allocator**: パケット構造体のプール化
- **Ring Buffer**: 連続するパケット番号に最適化
- **Custom Hash Table**: QUIC 特有のアクセスパターンに最適化

## Files

| ファイル | 責務 | RFC参照 |
|---------|------|--------|
| `LossDetector.swift` | パケットロス検出 | RFC 9002 Section 4 |
| `AckManager.swift` | ACKフレーム生成 | RFC 9002 Section 3 |
| `RTTEstimator.swift` | RTT推定 | RFC 9002 Section 5 |
| `SentPacket.swift` | 送信パケット追跡 | RFC 9002 Appendix A.1.1 |
| `CongestionController.swift` | 輻輳制御プロトコル | RFC 9002 Section 7 |
| `NewRenoCongestionController.swift` | NewReno実装 | RFC 9002 Section 7 |
| `PacketNumberSpaceManager.swift` | パケット番号空間統合管理 | RFC 9002 Section 6 |
| `LossDetectionConstants.swift` | RFC定数定義 | RFC 9002 |

## Testing

### ユニットテスト

```bash
swift test --filter QUICRecoveryTests
```

### ベンチマーク

```bash
swift test --filter "Recovery Performance Benchmarks"
```

### プロファイリング

```bash
swift test --filter "ProfilingTests"
```
