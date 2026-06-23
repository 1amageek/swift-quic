/// TLS 1.3 Signature Algorithms Extension (RFC 8446 Section 4.2.3)
///
/// ```
/// struct {
///     SignatureScheme supported_signature_algorithms<2..2^16-2>;
/// } SignatureSchemeList;
/// ```

import P2PCoreBytes

// MARK: - Signature Algorithms Extension

/// Signature algorithms extension
public struct SignatureAlgorithmsExtension: Sendable, TLSExtensionValue {
    public static var extensionType: TLSExtensionType { .signatureAlgorithms }

    /// List of supported signature algorithms in preference order
    public let supportedSignatureAlgorithms: [SignatureScheme]

    public init(supportedSignatureAlgorithms: [SignatureScheme]) {
        self.supportedSignatureAlgorithms = supportedSignatureAlgorithms
    }

    /// Default signature algorithms for TLS 1.3
    public static var `default`: SignatureAlgorithmsExtension {
        SignatureAlgorithmsExtension(supportedSignatureAlgorithms: [
            .ecdsa_secp256r1_sha256,
            .ecdsa_secp384r1_sha384,
            .rsa_pss_rsae_sha256,
            .rsa_pss_rsae_sha384,
            .rsa_pss_rsae_sha512,
            .ed25519
        ])
    }

    public func encodeBytes() throws(TLSWireError) -> [UInt8] {
        var algorithmsData = [UInt8]()
        algorithmsData.reserveCapacity(supportedSignatureAlgorithms.count * 2)
        for scheme in supportedSignatureAlgorithms {
            algorithmsData.append(UInt8((scheme.rawValue >> 8) & 0xFF))
            algorithmsData.append(UInt8(scheme.rawValue & 0xFF))
        }

        var writer = ByteWriter(reservingCapacity: 2 + algorithmsData.count)
        try writer.wWriteVector16(algorithmsData)
        return writer.finishArray()
    }

    public static func decode(from data: [UInt8]) throws(TLSWireError) -> SignatureAlgorithmsExtension {
        var reader = ByteReader(data)
        let algorithmsData = try reader.wReadVector16()

        guard algorithmsData.count >= 2 && algorithmsData.count % 2 == 0 else {
            throw TLSWireError.invalidFormat("Invalid signature algorithms length")
        }

        var algorithms: [SignatureScheme] = []
        var algReader = ByteReader(algorithmsData)
        while !algReader.isAtEnd {
            let value = try algReader.wReadUInt16()
            if let scheme = SignatureScheme(rawValue: value) {
                algorithms.append(scheme)
            }
            // Unknown schemes are ignored
        }

        return SignatureAlgorithmsExtension(supportedSignatureAlgorithms: algorithms)
    }

    /// Check if a signature scheme is supported
    public func supports(_ scheme: SignatureScheme) -> Bool {
        supportedSignatureAlgorithms.contains(scheme)
    }

    /// Find the first mutually supported signature scheme
    public func findCommon(with other: SignatureAlgorithmsExtension) -> SignatureScheme? {
        for scheme in supportedSignatureAlgorithms {
            if other.supports(scheme) {
                return scheme
            }
        }
        return nil
    }
}
