import NetworkingCore
import QUICWire
import SSLCrypto

/// RFC 9001 section 5.8 Retry integrity computation and verification.
///
/// Retry authentication uses a version-specific fixed AES-128-GCM key and
/// nonce. The Retry packet bytes are authenticated data and the plaintext is
/// empty, so the resulting sealed output is exactly the 16-byte integrity tag.
public enum RetryIntegrityCore {
    public static let tagLength = ProtocolLimits.retryIntegrityTagLength

    public static func compute(
        originalDestinationConnectionID: ConnectionID,
        retryPacketWithoutTag: Span<UInt8>,
        version: QUICVersion
    ) throws(PacketProtectionError) -> [UInt8] {
        guard originalDestinationConnectionID.bytes.count <= ProtocolLimits.maxConnectionIDLength else {
            throw .invalidRetryConnectionIDLength(
                actual: originalDestinationConnectionID.bytes.count
            )
        }
        guard let key = version.retryIntegrityKeyBytes,
              let nonce = version.retryIntegrityNonceBytes else {
            throw .unsupportedRetryVersion(version.rawValue)
        }

        var pseudoPacket = [UInt8]()
        pseudoPacket.reserveCapacity(
            1 + originalDestinationConnectionID.bytes.count + retryPacketWithoutTag.count
        )
        pseudoPacket.append(UInt8(originalDestinationConnectionID.bytes.count))
        pseudoPacket.append(contentsOf: originalDestinationConnectionID.bytes)
        for index in 0..<retryPacketWithoutTag.count {
            pseudoPacket.append(retryPacketWithoutTag[index])
        }

        do throws(AEADError) {
            let aead = try AESGCM(key: key.span)
            var tag = [UInt8](repeating: 0, count: tagLength)
            var destination = tag.mutableSpan
            try aead.seal(
                plaintext: [UInt8]().span,
                authenticatedData: pseudoPacket.span,
                nonce: nonce.span,
                into: &destination
            )
            return tag
        } catch let error {
            throw .aead(error)
        }
    }

    public static func verify(
        tag: Span<UInt8>,
        originalDestinationConnectionID: ConnectionID,
        retryPacketWithoutTag: Span<UInt8>,
        version: QUICVersion
    ) throws(PacketProtectionError) -> Bool {
        guard tag.count == tagLength else {
            throw .invalidRetryIntegrityTagLength(expected: tagLength, actual: tag.count)
        }
        let expected = try compute(
            originalDestinationConnectionID: originalDestinationConnectionID,
            retryPacketWithoutTag: retryPacketWithoutTag,
            version: version
        )
        var difference: UInt8 = 0
        for index in 0..<tagLength {
            difference |= tag[index] ^ expected[index]
        }
        return difference == 0
    }
}
