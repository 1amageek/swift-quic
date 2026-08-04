/// Frames complete TLS handshake messages from ordered QUIC CRYPTO bytes.
///
/// This is transport framing, not TLS semantics. The owner retains bytes that
/// end at a partial four-byte TLS handshake header or body and emits only
/// header-inclusive complete messages. The storage is private to the caller's
/// value-type engine; no borrowed view escapes this type.
struct QUICCryptoMessageFramer: Sendable {
    static let headerByteCount = 4
    static let protocolMaximumMessageByteCount = 0x00FF_FFFF + headerByteCount

    private var storage: [UInt8] = []
    private var readIndex = 0

    mutating func append(
        _ bytes: [UInt8]
    ) throws(QUICEngineError) -> [[UInt8]] {
        guard !bytes.isEmpty else { return [] }
        storage.append(contentsOf: bytes)

        var messages: [[UInt8]] = []
        while true {
            let available = storage.count - readIndex
            guard available >= Self.headerByteCount else { break }

            let bodyByteCount =
                (Int(storage[readIndex + 1]) << 16) |
                (Int(storage[readIndex + 2]) << 8) |
                Int(storage[readIndex + 3])
            let messageByteCount = Self.headerByteCount + bodyByteCount
            guard messageByteCount <= Self.protocolMaximumMessageByteCount else {
                throw .cryptoClosureFailed(
                    "TLS handshake message exceeds the QUIC framing limit"
                )
            }
            guard available >= messageByteCount else { break }

            let endIndex = readIndex + messageByteCount
            messages.append(Array(storage[readIndex..<endIndex]))
            readIndex = endIndex
        }

        compactIfNeeded()
        return messages
    }

    private mutating func compactIfNeeded() {
        guard readIndex > 0 else { return }
        guard readIndex == storage.count || readIndex >= 4096 else { return }
        storage.removeFirst(readIndex)
        readIndex = 0
    }
}
