/// Public Key Extraction from X.509 Certificates
///
/// Extracts public keys from SubjectPublicKeyInfo (SPKI) structures
/// and converts them to VerificationKey for signature verification.

import Foundation
import Crypto

// MARK: - Public Key Extraction

extension X509Certificate {
    /// Extracts the public key from this certificate as a VerificationKey
    public func extractPublicKey() throws -> VerificationKey {
        try subjectPublicKeyInfo.toVerificationKey()
    }

    /// Extracts the raw public key bytes
    public func extractPublicKeyBytes() -> Data {
        subjectPublicKeyInfo.subjectPublicKey
    }
}

extension SubjectPublicKeyInfo {
    /// Converts this SPKI to a VerificationKey
    public func toVerificationKey() throws -> VerificationKey {
        guard let knownAlg = algorithm.knownAlgorithm else {
            throw X509Error.unsupportedPublicKeyAlgorithm(algorithm.algorithm.dotNotation)
        }

        switch knownAlg {
        case .ecPublicKey:
            return try extractECPublicKey()
        case .ed25519:
            return try extractEd25519PublicKey()
        case .rsaEncryption:
            throw X509Error.unsupportedPublicKeyAlgorithm("RSA (not yet implemented)")
        default:
            throw X509Error.unsupportedPublicKeyAlgorithm(algorithm.algorithm.dotNotation)
        }
    }

    /// Extracts an EC public key
    private func extractECPublicKey() throws -> VerificationKey {
        // Determine the curve from parameters
        guard let curveOID = curveOID else {
            throw X509Error.missingCurveParameter
        }

        guard let knownCurve = KnownOID(oid: curveOID) else {
            throw X509Error.unsupportedCurve(curveOID.dotNotation)
        }

        // Public key is in uncompressed point format: 04 || X || Y
        let keyData = subjectPublicKey

        switch knownCurve {
        case .secp256r1:
            // P-256 key (32 bytes each for X and Y)
            let key = try P256.Signing.PublicKey(x963Representation: keyData)
            return .p256(key)

        case .secp384r1:
            // P-384 key (48 bytes each for X and Y)
            let key = try P384.Signing.PublicKey(x963Representation: keyData)
            return .p384(key)

        case .secp521r1:
            // P-521 not yet supported
            throw X509Error.unsupportedCurve("secp521r1 (P-521)")

        default:
            throw X509Error.unsupportedCurve(curveOID.dotNotation)
        }
    }

    /// Extracts an Ed25519 public key
    private func extractEd25519PublicKey() throws -> VerificationKey {
        // Ed25519 public key is 32 bytes
        guard subjectPublicKey.count == 32 else {
            throw X509Error.invalidPublicKey("Ed25519 key must be 32 bytes, got \(subjectPublicKey.count)")
        }

        let key = try Curve25519.Signing.PublicKey(rawRepresentation: subjectPublicKey)
        return .ed25519(key)
    }
}

// MARK: - VerificationKey Extension for X.509

extension VerificationKey {
    /// Creates a VerificationKey from an X.509 certificate
    public init(certificate: X509Certificate) throws {
        self = try certificate.extractPublicKey()
    }

    /// Creates a VerificationKey from DER-encoded certificate data
    public init(certificateData: Data) throws {
        let cert = try X509Certificate.parse(from: certificateData)
        self = try cert.extractPublicKey()
    }

    /// Creates a VerificationKey from a SubjectPublicKeyInfo
    public init(spki: SubjectPublicKeyInfo) throws {
        self = try spki.toVerificationKey()
    }

    /// Creates a VerificationKey from DER-encoded SPKI data
    public init(spkiData: Data) throws {
        let value = try ASN1Parser.parseOne(from: spkiData)
        let spki = try SubjectPublicKeyInfo.parse(from: value)
        self = try spki.toVerificationKey()
    }
}

// MARK: - Signature Algorithm Mapping

extension AlgorithmIdentifier {
    /// Maps this algorithm to a SignatureScheme (if applicable)
    public var signatureScheme: SignatureScheme? {
        guard let known = knownAlgorithm else { return nil }

        switch known {
        case .ecdsaWithSHA256:
            return .ecdsa_secp256r1_sha256
        case .ecdsaWithSHA384:
            return .ecdsa_secp384r1_sha384
        case .ed25519:
            return .ed25519
        default:
            return nil
        }
    }
}
