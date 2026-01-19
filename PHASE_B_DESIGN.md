# Phase B 設計書 - 根本的な問題解決

## 概要

Phase B は以下の3つの問題を修正する:

1. **#1 ACK レンジ DoS** - LossDetector.swift
2. **#7 ヘッダ検証未使用** - PacketHeader.swift
3. **#8 STREAM オーバーヘッド誤差** - StreamManager.swift

これらは個別の問題に見えるが、共通の設計パターンの欠如が根本原因である。

---

## 根本原因と設計方針

### 問題 #1: ACK レンジ DoS

**現状のコード** (`LossDetector.swift:173-188`):
```swift
// 危険: O(range_length) - 攻撃者がレンジサイズを制御可能
for pn in checkStart...current {
    if let packet = state.sentPackets.removeValue(forKey: pn) {
        // ...
    }
}
```

**問題**: `checkStart...current` は攻撃者が送信した ACK フレームの値。
悪意ある巨大レンジ (例: 0...2^62) で CPU を浪費させる DoS 攻撃が可能。

**設計方針: Bounded Iteration**

信頼できないデータでイテレーションしない。代わりに:
- 既知のデータ構造 (`sentPackets.keys`) をイテレート
- 各キーがレンジ内かどうかを O(log n) で判定

**修正設計**:
```swift
// 安全: O(sentPackets.count * log(ranges))
// sentPackets は自分が送信したパケットなのでサイズは制御可能
for pn in state.sentPackets.keys {
    if isInAckRanges(pn, ranges: ackFrame.ackRanges, largest: largestAcked) {
        if let packet = state.sentPackets.removeValue(forKey: pn) {
            // ...
        }
    }
}

// ACK レンジ内かどうかを効率的に判定
private func isInAckRanges(_ pn: UInt64, ranges: [AckRange], largest: UInt64) -> Bool {
    var current = largest
    for (index, range) in ranges.enumerated() {
        let rangeEnd: UInt64
        let rangeStart: UInt64

        if index == 0 {
            rangeEnd = current
            guard range.rangeLength <= current else { return false }
            rangeStart = current - range.rangeLength
        } else {
            let gapOffset = range.gap + 2
            guard gapOffset <= current else { return false }
            current = current - gapOffset
            rangeEnd = current
            guard range.rangeLength <= current else { return false }
            rangeStart = current - range.rangeLength
        }

        if pn >= rangeStart && pn <= rangeEnd {
            return true
        }

        // pn がこのレンジより大きければ、以降のレンジにも含まれない
        // (レンジは降順なので)
        if pn > rangeEnd {
            return false
        }

        current = rangeStart
    }
    return false
}
```

**計算量比較**:
| 方式 | 計算量 | 攻撃時の影響 |
|------|--------|-------------|
| 現状 | O(Σ range_length) | 最大 O(2^62) |
| 修正 | O(sentPackets × ranges) | 最大 O(1000 × 256) = O(256,000) |

---

### 問題 #7: ヘッダ検証未使用

**現状**: `LongHeader.validate()` と `ShortHeader.validate()` は定義されているが、
パケット処理パイプラインで呼ばれていない。

**問題の本質**: 検証がオプショナルで、呼び忘れるリスクがある。

**設計方針: Parse-Validate-Process パイプライン**

検証をパースの一部として統合し、デフォルトで有効にする。

**修正設計**:

```swift
// PacketHeader.swift に追加

extension PacketHeader {
    /// Parses and validates a packet header
    /// - Parameters:
    ///   - data: The packet data
    ///   - dcidLength: For short headers, the expected DCID length
    ///   - validate: Whether to validate the header (default: true)
    ///   - strictValidation: Whether to check reserved bits (default: false)
    /// - Returns: The parsed and validated header
    public static func parse(
        from data: Data,
        dcidLength: Int = 0,
        validate: Bool = true,
        strictValidation: Bool = false
    ) throws -> (header: PacketHeader, headerLength: Int) {
        // 既存のパースロジック
        let (header, length) = try parseInternal(from: data, dcidLength: dcidLength)

        // 検証 (デフォルトで有効)
        if validate {
            switch header {
            case .long(let longHeader):
                try longHeader.validate(strict: strictValidation)
            case .short(let shortHeader):
                try shortHeader.validate(strict: strictValidation)
            }
        }

        return (header, length)
    }
}
```

**PacketDecoder での統合**:

```swift
// PacketDecoder.swift (または PacketCodec.swift)

public func decodePacket(
    data: Data,
    dcidLength: Int,
    opener: any PacketOpener,
    largestPN: UInt64
) throws -> ParsedPacket {
    // 1. ヘッダーパース（検証込み）
    let (header, headerLength) = try PacketHeader.parse(
        from: data,
        dcidLength: dcidLength,
        validate: true  // デフォルトで検証
    )

    // 2. ヘッダー保護除去
    // ...

    // 3. 復号
    // ...
}
```

---

### 問題 #8: STREAM オーバーヘッド誤差

**現状** (`StreamManager.swift:497`):
```swift
remainingBytes -= 11 + frame.data.count  // Approximate overhead
```

**問題**: STREAM フレームのオーバーヘッドは可変:
- Type: 1 byte
- Stream ID: 1-8 bytes (varint)
- Offset: 0-8 bytes (varint, 非ゼロの場合のみ)
- Length: 0-8 bytes (varint, hasLength の場合のみ)

実際のオーバーヘッドは 1〜25 bytes で、11 は不正確。

**設計方針: Single Source of Truth**

フレームサイズ計算を一箇所に集約し、エンコード時も同じロジックを使用する。

**修正設計**:

```swift
// FrameSize.swift (新規ファイル)

/// フレームサイズ計算ユーティリティ
public enum FrameSize {

    /// STREAM フレームのエンコードサイズを計算
    /// - Parameters:
    ///   - streamID: ストリーム ID
    ///   - offset: データオフセット
    ///   - dataLength: データ長
    ///   - hasLength: Length フィールドを含むか
    /// - Returns: フレーム全体のバイト数
    public static func streamFrame(
        streamID: UInt64,
        offset: UInt64,
        dataLength: Int,
        hasLength: Bool
    ) -> Int {
        var size = 1  // Type byte
        size += Varint.encodedLength(streamID)

        if offset > 0 {
            size += Varint.encodedLength(offset)
        }

        if hasLength {
            size += Varint.encodedLength(UInt64(dataLength))
        }

        size += dataLength
        return size
    }

    /// STREAM フレームのオーバーヘッド（データ部分を除く）を計算
    public static func streamFrameOverhead(
        streamID: UInt64,
        offset: UInt64,
        dataLength: Int,
        hasLength: Bool
    ) -> Int {
        streamFrame(streamID: streamID, offset: offset, dataLength: dataLength, hasLength: hasLength) - dataLength
    }

    /// ACK フレームのエンコードサイズを計算
    public static func ackFrame(_ frame: AckFrame) -> Int {
        var size = 1  // Type byte
        size += Varint.encodedLength(frame.largestAcknowledged)
        size += Varint.encodedLength(frame.ackDelay)
        size += Varint.encodedLength(UInt64(max(0, frame.ackRanges.count - 1)))

        for (index, range) in frame.ackRanges.enumerated() {
            if index == 0 {
                size += Varint.encodedLength(range.rangeLength)
            } else {
                size += Varint.encodedLength(range.gap)
                size += Varint.encodedLength(range.rangeLength)
            }
        }

        if let ecn = frame.ecnCounts {
            size += Varint.encodedLength(ecn.ect0Count)
            size += Varint.encodedLength(ecn.ect1Count)
            size += Varint.encodedLength(ecn.ecnCECount)
        }

        return size
    }

    /// 任意のフレームのエンコードサイズを計算
    public static func frame(_ frame: Frame) -> Int {
        switch frame {
        case .padding(let count):
            return count
        case .ping:
            return 1
        case .ack(let ack):
            return ackFrame(ack)
        case .stream(let sf):
            return streamFrame(
                streamID: sf.streamID,
                offset: sf.offset,
                dataLength: sf.data.count,
                hasLength: sf.hasLength
            )
        // ... 他のフレームタイプ
        default:
            // フォールバック: 実際にエンコードしてサイズを取得
            // (パフォーマンス低下を避けるため、主要フレームは明示的に計算)
            let codec = StandardFrameCodec()
            return (try? codec.encode(frame).count) ?? 0
        }
    }
}

// Varint.swift に追加
extension Varint {
    /// varint のエンコード長を計算（実際にエンコードせずに）
    public static func encodedLength(_ value: UInt64) -> Int {
        if value < 64 { return 1 }
        if value < 16384 { return 2 }
        if value < 1073741824 { return 4 }
        return 8
    }
}
```

**StreamManager での使用**:

```swift
// StreamManager.swift:generateStreamFrames

for frame in streamFrames {
    // 正確なオーバーヘッド計算
    let frameSize = FrameSize.streamFrame(
        streamID: frame.streamID,
        offset: frame.offset,
        dataLength: frame.data.count,
        hasLength: frame.hasLength
    )

    state.flowController.recordBytesSent(UInt64(frame.data.count))
    remainingBytes -= frameSize
}
```

---

## ファイル変更一覧

| ファイル | 変更内容 | 優先度 |
|---------|---------|--------|
| `Sources/QUICCore/FrameSize.swift` | 新規作成 - フレームサイズ計算 | P0 |
| `Sources/QUICCore/Varint.swift` | `encodedLength()` 追加 | P0 |
| `Sources/QUICRecovery/LossDetector.swift` | `processAckedRanges` を安全なイテレーションに変更 | P0 |
| `Sources/QUICCore/Packet/PacketHeader.swift` | `parse()` に検証統合 | P1 |
| `Sources/QUIC/PacketDecoder.swift` | 検証付きパースを使用 | P1 |
| `Sources/QUICStream/StreamManager.swift` | `FrameSize` を使用 | P1 |

---

## 実装順序

```
Step 1: 基盤作成
  ├── Varint.encodedLength() 追加
  └── FrameSize.swift 新規作成

Step 2: ACK DoS 修正 (#1)
  ├── isInAckRanges() ヘルパー追加
  └── processAckedRanges() を安全なイテレーションに変更

Step 3: ヘッダ検証統合 (#7)
  ├── PacketHeader.parse() に validate パラメータ追加
  └── PacketDecoder で検証付きパースを使用

Step 4: STREAM オーバーヘッド修正 (#8)
  └── StreamManager.generateStreamFrames() で FrameSize を使用

Step 5: テスト
  ├── FrameSize のユニットテスト
  ├── ACK DoS 攻撃のテスト
  └── 既存テストの確認
```

---

## 検証方法

### ACK DoS テスト

```swift
@Test("Malicious ACK range does not cause CPU exhaustion")
func testMaliciousAckRange() {
    let detector = LossDetector()

    // 10個のパケットを送信
    for pn: UInt64 in 0..<10 {
        detector.onPacketSent(SentPacket(packetNumber: pn, ...))
    }

    // 攻撃: 巨大なレンジを持つ ACK フレーム
    let maliciousAck = AckFrame(
        largestAcknowledged: UInt64.max - 1,
        ackDelay: 0,
        ackRanges: [AckRange(gap: 0, rangeLength: UInt64.max - 10)]  // 巨大レンジ
    )

    // タイムアウト付きで実行（1秒以内に完了すべき）
    let start = CFAbsoluteTimeGetCurrent()
    _ = detector.onAckReceived(ackFrame: maliciousAck, ...)
    let elapsed = CFAbsoluteTimeGetCurrent() - start

    #expect(elapsed < 1.0, "ACK processing should complete quickly")
}
```

### FrameSize 精度テスト

```swift
@Test("FrameSize matches actual encoded size")
func testFrameSizeAccuracy() throws {
    let codec = StandardFrameCodec()

    // 様々なサイズの STREAM フレーム
    let testCases: [(UInt64, UInt64, Int)] = [
        (0, 0, 100),           // 最小 Stream ID, オフセット 0
        (63, 0, 100),          // 1バイト Stream ID
        (16383, 63, 1000),     // 2バイト Stream ID, 1バイト offset
        (1_000_000, 1_000_000, 10000),  // 大きな値
    ]

    for (streamID, offset, dataLen) in testCases {
        let frame = StreamFrame(
            streamID: streamID,
            offset: offset,
            data: Data(repeating: 0, count: dataLen),
            fin: false,
            hasLength: true
        )

        let predicted = FrameSize.streamFrame(
            streamID: streamID,
            offset: offset,
            dataLength: dataLen,
            hasLength: true
        )
        let actual = try codec.encode(.stream(frame)).count

        #expect(predicted == actual, "Predicted \(predicted) != actual \(actual)")
    }
}
```

---

## 設計の利点

1. **セキュリティ**: ACK DoS 攻撃を根本的に防止
2. **正確性**: フレームサイズ計算が常に正確
3. **保守性**: 検証がパイプラインに統合され、呼び忘れがない
4. **パフォーマンス**: 計算量が入力データではなく既知データに依存
