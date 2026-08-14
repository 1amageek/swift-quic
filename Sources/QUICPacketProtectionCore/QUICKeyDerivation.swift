import NetworkingCore
import QUICWire
import SSLCrypto

/// RFC 9001 packet-protection key schedule.
///
/// QUIC owns the TLS label encoding and packet-key semantics. `swift-ssl` owns
/// only the HKDF primitive. Inputs are borrowed and each derived result is
/// materialized exactly once in caller-owned output storage.
public enum QUICKeyDerivation {
    public static func expandLabel(
        secret: [UInt8],
        label: String,
        context: [UInt8],
        length: Int
    ) throws(PacketProtectionError) -> [UInt8] {
        guard length >= 0, let encodedLength = UInt16(exactly: length) else {
            throw .invalidDerivationOutputLength(actual: length)
        }
        let prefixedLabel = Array("tls13 \(label)".utf8)
        guard let encodedLabelLength = UInt8(exactly: prefixedLabel.count) else {
            throw .labelTooLong(limit: Int(UInt8.max), actual: prefixedLabel.count)
        }
        guard let encodedContextLength = UInt8(exactly: context.count) else {
            throw .contextTooLong(limit: Int(UInt8.max), actual: context.count)
        }

        var writer = QUICWireWriter(
            reservingCapacity: 4 + prefixedLabel.count + context.count
        )
        writer.writeUInt16(encodedLength)
        writer.writeUInt8(encodedLabelLength)
        writer.writeBytes(prefixedLabel)
        writer.writeUInt8(encodedContextLength)
        writer.writeBytes(context)
        let info = writer.finishArray()

        var output = [UInt8](repeating: 0, count: length)
        do throws(HKDFError) {
            var destination = output.mutableSpan
            try HKDFSHA256.expand(
                pseudorandomKey: secret.span,
                info: info.span,
                into: &destination
            )
            return output
        } catch let error {
            throw .keyDerivation(error)
        }
    }

    public static func initialSecret(
        connectionID: [UInt8],
        salt: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        var output = [UInt8](repeating: 0, count: HKDFSHA256.pseudorandomKeyByteCount)
        do throws(HKDFError) {
            var destination = output.mutableSpan
            try HKDFSHA256.extract(
                inputKeyMaterial: connectionID.span,
                salt: salt.span,
                into: &destination
            )
            return output
        } catch let error {
            throw .keyDerivation(error)
        }
    }

    public static func initialSecrets(
        connectionID: [UInt8],
        salt: [UInt8]
    ) throws(PacketProtectionError) -> (client: [UInt8], server: [UInt8]) {
        let initial = try initialSecret(connectionID: connectionID, salt: salt)
        let client = try expandLabel(secret: initial, label: "client in", context: [], length: 32)
        let server = try expandLabel(secret: initial, label: "server in", context: [], length: 32)
        return (client, server)
    }

    public static func packetKeys(
        secret: [UInt8],
        suite: QUICProtectionSuite
    ) throws(PacketProtectionError) -> (key: [UInt8], iv: [UInt8], hpKey: [UInt8]) {
        let keyLength = suite.keyLength
        let key = try expandLabel(secret: secret, label: "quic key", context: [], length: keyLength)
        let iv = try expandLabel(secret: secret, label: "quic iv", context: [], length: 12)
        let hpKey = try expandLabel(secret: secret, label: "quic hp", context: [], length: keyLength)
        return (key, iv, hpKey)
    }

    public static func protector(
        secret: [UInt8],
        suite: QUICProtectionSuite
    ) throws(PacketProtectionError) -> SuiteProtector {
        let (key, iv, hpKey) = try packetKeys(secret: secret, suite: suite)
        return try SuiteProtector.make(suite: suite, key: key, iv: iv, hpKey: hpKey)
    }

    public static func nextGenerationSecret(
        secret: [UInt8]
    ) throws(PacketProtectionError) -> [UInt8] {
        try expandLabel(secret: secret, label: "quic ku", context: [], length: 32)
    }
}
