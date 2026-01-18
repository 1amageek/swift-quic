/// X.509 Certificate (RFC 5280)
///
/// Represents a parsed X.509 v3 certificate.
///
/// ```
/// Certificate  ::=  SEQUENCE  {
///     tbsCertificate       TBSCertificate,
///     signatureAlgorithm   AlgorithmIdentifier,
///     signatureValue       BIT STRING  }
///
/// TBSCertificate  ::=  SEQUENCE  {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature            AlgorithmIdentifier,
///     issuer               Name,
///     validity             Validity,
///     subject              Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      [3]  EXPLICIT Extensions OPTIONAL }
/// ```

import Foundation

// MARK: - X.509 Certificate

/// A parsed X.509 certificate
public struct X509Certificate: Sendable {
    /// Certificate version (0 = v1, 1 = v2, 2 = v3)
    public let version: Int

    /// Serial number (unique within issuer)
    public let serialNumber: Data

    /// Signature algorithm used to sign the certificate
    public let signatureAlgorithm: AlgorithmIdentifier

    /// Certificate issuer (who signed this certificate)
    public let issuer: X509Name

    /// Validity period
    public let validity: X509Validity

    /// Certificate subject (who this certificate identifies)
    public let subject: X509Name

    /// Subject's public key information
    public let subjectPublicKeyInfo: SubjectPublicKeyInfo

    /// Extensions (v3 only)
    public let extensions: X509Extensions

    /// The TBS (To-Be-Signed) certificate bytes for signature verification
    public let tbsCertificateBytes: Data

    /// The signature value
    public let signatureValue: Data

    /// Original DER-encoded certificate
    public let derEncoded: Data

    // MARK: - Computed Properties

    /// Whether this is a self-signed certificate
    public var isSelfSigned: Bool {
        issuer == subject
    }

    /// Whether this is a CA certificate (based on BasicConstraints)
    public var isCA: Bool {
        extensions.basicConstraints?.isCA ?? false
    }

    /// Path length constraint (if any)
    public var pathLengthConstraint: Int? {
        extensions.basicConstraints?.pathLenConstraint
    }

    // MARK: - Parsing

    /// Parses an X.509 certificate from DER-encoded data
    public static func parse(from data: Data) throws -> X509Certificate {
        do {
            let root = try ASN1Parser.parseOne(from: data)
            return try parse(from: root, derEncoded: data)
        } catch let error as ASN1Error {
            throw X509Error.asn1Error(error)
        }
    }

    /// Parses an X.509 certificate from a parsed ASN.1 value
    static func parse(from root: ASN1Value, derEncoded: Data) throws -> X509Certificate {
        // Certificate is a SEQUENCE of 3 elements
        guard root.tag.isSequence, root.children.count == 3 else {
            throw X509Error.invalidCertificateStructure("Expected SEQUENCE of 3 elements")
        }

        // Parse TBSCertificate
        let tbsValue = root.children[0]
        let tbsCertificateBytes = tbsValue.rawBytes

        guard tbsValue.tag.isSequence else {
            throw X509Error.invalidCertificateStructure("TBSCertificate must be SEQUENCE")
        }

        var tbsIndex = 0

        // Version (optional, default v1)
        var version = 0
        if let versionTag = tbsValue.optionalChild(at: 0),
           versionTag.tag.tagClass == .contextSpecific,
           versionTag.tag.tagNumber == 0 {
            // Version is explicitly tagged [0]
            if let versionValue = versionTag.children.first {
                let versionBytes = try versionValue.asInteger()
                version = Int(versionBytes.first ?? 0)
            }
            tbsIndex += 1
        }

        // Serial Number
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("serialNumber")
        }
        let serialNumberValue = tbsValue.children[tbsIndex]
        let serialNumber = try serialNumberValue.asPositiveInteger()
        tbsIndex += 1

        // Signature Algorithm (in TBS)
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("signature")
        }
        let tbsSignatureAlg = try AlgorithmIdentifier.parse(from: tbsValue.children[tbsIndex])
        tbsIndex += 1

        // Issuer
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("issuer")
        }
        let issuer = try X509Name.parse(from: tbsValue.children[tbsIndex])
        tbsIndex += 1

        // Validity
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("validity")
        }
        let validity = try X509Validity.parse(from: tbsValue.children[tbsIndex])
        tbsIndex += 1

        // Subject
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("subject")
        }
        let subject = try X509Name.parse(from: tbsValue.children[tbsIndex])
        tbsIndex += 1

        // SubjectPublicKeyInfo
        guard tbsIndex < tbsValue.children.count else {
            throw X509Error.missingRequiredField("subjectPublicKeyInfo")
        }
        let spki = try SubjectPublicKeyInfo.parse(from: tbsValue.children[tbsIndex])
        tbsIndex += 1

        // Extensions (optional, context-specific [3])
        var extensions = X509Extensions()
        while tbsIndex < tbsValue.children.count {
            let child = tbsValue.children[tbsIndex]
            if child.tag.tagClass == .contextSpecific && child.tag.tagNumber == 3 {
                // Extensions
                if let extensionsSeq = child.children.first {
                    extensions = try X509Extensions.parse(from: extensionsSeq)
                }
            }
            tbsIndex += 1
        }

        // Parse outer signature algorithm
        let signatureAlgorithm = try AlgorithmIdentifier.parse(from: root.children[1])

        // Verify signature algorithms match
        guard signatureAlgorithm.algorithm == tbsSignatureAlg.algorithm else {
            throw X509Error.signatureAlgorithmMismatch
        }

        // Parse signature value (BIT STRING)
        let (_, signatureValue) = try root.children[2].asBitString()

        return X509Certificate(
            version: version,
            serialNumber: serialNumber,
            signatureAlgorithm: signatureAlgorithm,
            issuer: issuer,
            validity: validity,
            subject: subject,
            subjectPublicKeyInfo: spki,
            extensions: extensions,
            tbsCertificateBytes: tbsCertificateBytes,
            signatureValue: signatureValue,
            derEncoded: derEncoded
        )
    }
}

// MARK: - Algorithm Identifier

/// Algorithm identifier with optional parameters
public struct AlgorithmIdentifier: Sendable, Equatable {
    /// Algorithm OID
    public let algorithm: OID

    /// Algorithm parameters (optional)
    public let parameters: Data?

    /// Parses an AlgorithmIdentifier from ASN.1
    public static func parse(from value: ASN1Value) throws -> AlgorithmIdentifier {
        guard value.tag.isSequence, value.children.count >= 1 else {
            throw X509Error.invalidCertificateStructure("AlgorithmIdentifier must be SEQUENCE")
        }

        let algorithm = try value.children[0].asObjectIdentifier()

        var parameters: Data? = nil
        if value.children.count > 1 {
            // Parameters are optional and can be any type
            let paramValue = value.children[1]
            // Store raw bytes if not NULL
            if paramValue.tag.universalTag != .null {
                parameters = paramValue.rawBytes
            }
        }

        return AlgorithmIdentifier(algorithm: algorithm, parameters: parameters)
    }

    /// The known algorithm type if recognized
    public var knownAlgorithm: KnownOID? {
        KnownOID(oid: algorithm)
    }
}

// MARK: - X.509 Name

/// X.509 Distinguished Name (DN)
public struct X509Name: Sendable, Equatable, Hashable {
    /// Relative Distinguished Names in order
    public let rdnSequence: [RelativeDistinguishedName]

    /// Common Name (CN)
    public var commonName: String? {
        findAttribute(.commonName)
    }

    /// Organization (O)
    public var organization: String? {
        findAttribute(.organizationName)
    }

    /// Organizational Unit (OU)
    public var organizationalUnit: String? {
        findAttribute(.organizationalUnitName)
    }

    /// Country (C)
    public var country: String? {
        findAttribute(.countryName)
    }

    /// State/Province (ST)
    public var stateOrProvince: String? {
        findAttribute(.stateOrProvinceName)
    }

    /// Locality (L)
    public var locality: String? {
        findAttribute(.localityName)
    }

    private func findAttribute(_ oid: KnownOID) -> String? {
        for rdn in rdnSequence {
            for attr in rdn.attributes {
                if attr.type.dotNotation == oid.rawValue {
                    return attr.value
                }
            }
        }
        return nil
    }

    /// Parses an X.509 Name from ASN.1
    public static func parse(from value: ASN1Value) throws -> X509Name {
        guard value.tag.isSequence else {
            throw X509Error.invalidCertificateStructure("Name must be SEQUENCE")
        }

        var rdnSequence: [RelativeDistinguishedName] = []

        for rdnSet in value.children {
            let rdn = try RelativeDistinguishedName.parse(from: rdnSet)
            rdnSequence.append(rdn)
        }

        return X509Name(rdnSequence: rdnSequence)
    }

    /// Returns a string representation (e.g., "CN=example.com, O=Example Inc")
    public var string: String {
        rdnSequence.flatMap { $0.attributes }
            .map { attr in
                let typeStr = KnownOID(oid: attr.type)?.name ?? attr.type.dotNotation
                return "\(typeStr)=\(attr.value)"
            }
            .joined(separator: ", ")
    }
}

// MARK: - Relative Distinguished Name

/// A single RDN in a distinguished name
public struct RelativeDistinguishedName: Sendable, Equatable, Hashable {
    /// Attributes in this RDN
    public let attributes: [AttributeTypeAndValue]

    public static func parse(from value: ASN1Value) throws -> RelativeDistinguishedName {
        guard value.tag.isSet else {
            throw X509Error.invalidCertificateStructure("RDN must be SET")
        }

        var attributes: [AttributeTypeAndValue] = []

        for attrValue in value.children {
            let attr = try AttributeTypeAndValue.parse(from: attrValue)
            attributes.append(attr)
        }

        return RelativeDistinguishedName(attributes: attributes)
    }
}

// MARK: - Attribute Type and Value

/// An attribute type and value pair
public struct AttributeTypeAndValue: Sendable, Equatable, Hashable {
    /// Attribute type OID
    public let type: OID

    /// Attribute value as string
    public let value: String

    public static func parse(from value: ASN1Value) throws -> AttributeTypeAndValue {
        guard value.tag.isSequence, value.children.count == 2 else {
            throw X509Error.invalidCertificateStructure("AttributeTypeAndValue must be SEQUENCE of 2")
        }

        let type = try value.children[0].asObjectIdentifier()
        let valueStr = try value.children[1].asString()

        return AttributeTypeAndValue(type: type, value: valueStr)
    }
}

// MARK: - X.509 Validity

/// Certificate validity period
public struct X509Validity: Sendable {
    /// Not valid before this time
    public let notBefore: Date

    /// Not valid after this time
    public let notAfter: Date

    /// Checks if the certificate is valid at the given time
    public func isValid(at date: Date = Date()) -> Bool {
        date >= notBefore && date <= notAfter
    }

    /// Parses Validity from ASN.1
    public static func parse(from value: ASN1Value) throws -> X509Validity {
        guard value.tag.isSequence, value.children.count == 2 else {
            throw X509Error.invalidCertificateStructure("Validity must be SEQUENCE of 2")
        }

        let notBefore = try value.children[0].asTime()
        let notAfter = try value.children[1].asTime()

        return X509Validity(notBefore: notBefore, notAfter: notAfter)
    }
}

// MARK: - Subject Public Key Info

/// Subject Public Key Info (SPKI)
public struct SubjectPublicKeyInfo: Sendable {
    /// Algorithm identifier
    public let algorithm: AlgorithmIdentifier

    /// Public key bits
    public let subjectPublicKey: Data

    /// Raw DER-encoded SPKI bytes
    public let derEncoded: Data

    /// Parses SPKI from ASN.1
    public static func parse(from value: ASN1Value) throws -> SubjectPublicKeyInfo {
        guard value.tag.isSequence, value.children.count == 2 else {
            throw X509Error.invalidCertificateStructure("SubjectPublicKeyInfo must be SEQUENCE of 2")
        }

        let algorithm = try AlgorithmIdentifier.parse(from: value.children[0])
        let (_, publicKeyBits) = try value.children[1].asBitString()

        return SubjectPublicKeyInfo(
            algorithm: algorithm,
            subjectPublicKey: publicKeyBits,
            derEncoded: value.rawBytes
        )
    }

    /// Gets the curve OID for EC keys
    public var curveOID: OID? {
        guard let params = algorithm.parameters else { return nil }
        // Parameters should be an OID for EC keys
        do {
            let paramValue = try ASN1Parser.parseOne(from: params)
            return try paramValue.asObjectIdentifier()
        } catch {
            return nil
        }
    }
}

// MARK: - CustomStringConvertible

extension X509Certificate: CustomStringConvertible {
    public var description: String {
        """
        X509Certificate {
            version: v\(version + 1)
            serialNumber: \(serialNumber.hexString)
            issuer: \(issuer.string)
            subject: \(subject.string)
            validity: \(validity.notBefore) - \(validity.notAfter)
            algorithm: \(signatureAlgorithm.algorithm)
            isCA: \(isCA)
        }
        """
    }
}

// MARK: - Data Extension

extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
