/// X.509 Certificate Extensions (RFC 5280 Section 4.2)
///
/// Handles parsing of standard X.509 v3 extensions.

import Foundation

// MARK: - X.509 Extensions Container

/// Container for parsed X.509 extensions
public struct X509Extensions: Sendable {
    /// Basic Constraints extension
    public var basicConstraints: BasicConstraints?

    /// Key Usage extension
    public var keyUsage: KeyUsage?

    /// Extended Key Usage extension
    public var extendedKeyUsage: ExtendedKeyUsage?

    /// Subject Alternative Name extension
    public var subjectAltName: SubjectAltName?

    /// Authority Key Identifier extension
    public var authorityKeyIdentifier: AuthorityKeyIdentifier?

    /// Subject Key Identifier extension
    public var subjectKeyIdentifier: Data?

    /// All extensions (including unrecognized ones)
    public var allExtensions: [X509Extension] = []

    /// Parses extensions from ASN.1 SEQUENCE
    public static func parse(from value: ASN1Value) throws -> X509Extensions {
        guard value.tag.isSequence else {
            throw X509Error.invalidCertificateStructure("Extensions must be SEQUENCE")
        }

        var extensions = X509Extensions()

        for extValue in value.children {
            let ext = try X509Extension.parse(from: extValue)
            extensions.allExtensions.append(ext)

            // Parse known extensions
            if let knownOID = KnownOID(oid: ext.extnID) {
                try extensions.parseKnownExtension(knownOID, ext: ext)
            }
        }

        return extensions
    }

    private mutating func parseKnownExtension(_ oid: KnownOID, ext: X509Extension) throws {
        switch oid {
        case .basicConstraints:
            basicConstraints = try BasicConstraints.parse(from: ext.extnValue)
        case .keyUsage:
            keyUsage = try KeyUsage.parse(from: ext.extnValue)
        case .extKeyUsage:
            extendedKeyUsage = try ExtendedKeyUsage.parse(from: ext.extnValue)
        case .subjectAltName:
            subjectAltName = try SubjectAltName.parse(from: ext.extnValue)
        case .authorityKeyIdentifier:
            authorityKeyIdentifier = try AuthorityKeyIdentifier.parse(from: ext.extnValue)
        case .subjectKeyIdentifier:
            subjectKeyIdentifier = try parseSubjectKeyIdentifier(from: ext.extnValue)
        default:
            // Unknown or unhandled extension
            break
        }
    }

    private func parseSubjectKeyIdentifier(from data: Data) throws -> Data {
        let value = try ASN1Parser.parseOne(from: data)
        return try value.asOctetString()
    }

    public init() {}
}

// MARK: - X.509 Extension

/// A single X.509 extension
public struct X509Extension: Sendable {
    /// Extension OID
    public let extnID: OID

    /// Whether this extension is critical
    public let critical: Bool

    /// Extension value (DER-encoded)
    public let extnValue: Data

    public static func parse(from value: ASN1Value) throws -> X509Extension {
        guard value.tag.isSequence, value.children.count >= 2 else {
            throw X509Error.invalidCertificateStructure("Extension must be SEQUENCE of at least 2")
        }

        let extnID = try value.children[0].asObjectIdentifier()

        var critical = false
        var extnValueData: Data

        if value.children.count == 3 {
            // Has critical flag
            critical = try value.children[1].asBoolean()
            extnValueData = try value.children[2].asOctetString()
        } else {
            // No critical flag (defaults to false)
            extnValueData = try value.children[1].asOctetString()
        }

        return X509Extension(extnID: extnID, critical: critical, extnValue: extnValueData)
    }
}

// MARK: - Basic Constraints

/// Basic Constraints extension (RFC 5280 Section 4.2.1.9)
///
/// ```
/// BasicConstraints ::= SEQUENCE {
///     cA                      BOOLEAN DEFAULT FALSE,
///     pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
/// ```
public struct BasicConstraints: Sendable {
    /// Whether this is a CA certificate
    public let isCA: Bool

    /// Maximum number of intermediate CA certificates allowed
    public let pathLenConstraint: Int?

    public static func parse(from data: Data) throws -> BasicConstraints {
        let value = try ASN1Parser.parseOne(from: data)

        guard value.tag.isSequence else {
            throw X509Error.invalidExtension(oid: "basicConstraints", reason: "Must be SEQUENCE")
        }

        var isCA = false
        var pathLenConstraint: Int? = nil

        if let caValue = value.optionalChild(at: 0), caValue.tag.universalTag == .boolean {
            isCA = try caValue.asBoolean()

            if let pathLenValue = value.optionalChild(at: 1), pathLenValue.tag.isInteger {
                let bytes = try pathLenValue.asInteger()
                pathLenConstraint = bytes.reduce(0) { ($0 << 8) | Int($1) }
            }
        }

        return BasicConstraints(isCA: isCA, pathLenConstraint: pathLenConstraint)
    }
}

// MARK: - Key Usage

/// Key Usage extension (RFC 5280 Section 4.2.1.3)
///
/// ```
/// KeyUsage ::= BIT STRING {
///     digitalSignature        (0),
///     nonRepudiation          (1),
///     keyEncipherment         (2),
///     dataEncipherment        (3),
///     keyAgreement            (4),
///     keyCertSign             (5),
///     cRLSign                 (6),
///     encipherOnly            (7),
///     decipherOnly            (8) }
/// ```
public struct KeyUsage: Sendable, OptionSet {
    public let rawValue: UInt16

    public init(rawValue: UInt16) {
        self.rawValue = rawValue
    }

    public static let digitalSignature = KeyUsage(rawValue: 1 << 0)
    public static let nonRepudiation = KeyUsage(rawValue: 1 << 1)
    public static let keyEncipherment = KeyUsage(rawValue: 1 << 2)
    public static let dataEncipherment = KeyUsage(rawValue: 1 << 3)
    public static let keyAgreement = KeyUsage(rawValue: 1 << 4)
    public static let keyCertSign = KeyUsage(rawValue: 1 << 5)
    public static let cRLSign = KeyUsage(rawValue: 1 << 6)
    public static let encipherOnly = KeyUsage(rawValue: 1 << 7)
    public static let decipherOnly = KeyUsage(rawValue: 1 << 8)

    public static func parse(from data: Data) throws -> KeyUsage {
        let value = try ASN1Parser.parseOne(from: data)
        let (unusedBits, bitData) = try value.asBitString()

        guard !bitData.isEmpty else {
            return KeyUsage(rawValue: 0)
        }

        var rawValue: UInt16 = 0

        // In ASN.1 BIT STRING, bit 0 is the MSB of the first byte
        // KeyUsage: digitalSignature(0), nonRepudiation(1), ... keyCertSign(5), ...
        for (byteIndex, byte) in bitData.enumerated() {
            // Calculate significant bits in this byte
            let significantBits = (byteIndex == bitData.count - 1) ? (8 - Int(unusedBits)) : 8

            for bitIndex in 0..<significantBits {
                // Check if bit at position bitIndex (from MSB) is set
                if byte & (0x80 >> bitIndex) != 0 {
                    let keyUsageBit = byteIndex * 8 + bitIndex
                    rawValue |= UInt16(1 << keyUsageBit)
                }
            }
        }

        return KeyUsage(rawValue: rawValue)
    }
}

// MARK: - Extended Key Usage

/// Extended Key Usage extension (RFC 5280 Section 4.2.1.12)
public struct ExtendedKeyUsage: Sendable {
    /// Key purpose OIDs
    public let keyPurposes: [OID]

    /// Common key purposes
    public static let serverAuth = "1.3.6.1.5.5.7.3.1"
    public static let clientAuth = "1.3.6.1.5.5.7.3.2"
    public static let codeSigning = "1.3.6.1.5.5.7.3.3"
    public static let emailProtection = "1.3.6.1.5.5.7.3.4"
    public static let timeStamping = "1.3.6.1.5.5.7.3.8"
    public static let ocspSigning = "1.3.6.1.5.5.7.3.9"

    /// Whether this certificate can be used for TLS server authentication
    public var isServerAuth: Bool {
        keyPurposes.contains { $0.dotNotation == Self.serverAuth }
    }

    /// Whether this certificate can be used for TLS client authentication
    public var isClientAuth: Bool {
        keyPurposes.contains { $0.dotNotation == Self.clientAuth }
    }

    public static func parse(from data: Data) throws -> ExtendedKeyUsage {
        let value = try ASN1Parser.parseOne(from: data)

        guard value.tag.isSequence else {
            throw X509Error.invalidExtension(oid: "extKeyUsage", reason: "Must be SEQUENCE")
        }

        var keyPurposes: [OID] = []
        for child in value.children {
            let oid = try child.asObjectIdentifier()
            keyPurposes.append(oid)
        }

        return ExtendedKeyUsage(keyPurposes: keyPurposes)
    }
}

// MARK: - Subject Alternative Name

/// Subject Alternative Name extension (RFC 5280 Section 4.2.1.6)
///
/// ```
/// SubjectAltName ::= GeneralNames
/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
/// GeneralName ::= CHOICE {
///     otherName                       [0]     OtherName,
///     rfc822Name                      [1]     IA5String,
///     dNSName                         [2]     IA5String,
///     x400Address                     [3]     ORAddress,
///     directoryName                   [4]     Name,
///     ediPartyName                    [5]     EDIPartyName,
///     uniformResourceIdentifier       [6]     IA5String,
///     iPAddress                       [7]     OCTET STRING,
///     registeredID                    [8]     OBJECT IDENTIFIER }
/// ```
public struct SubjectAltName: Sendable {
    /// DNS names (dNSName)
    public let dnsNames: [String]

    /// Email addresses (rfc822Name)
    public let emailAddresses: [String]

    /// URIs (uniformResourceIdentifier)
    public let uris: [String]

    /// IP addresses (iPAddress)
    public let ipAddresses: [Data]

    public static func parse(from data: Data) throws -> SubjectAltName {
        let value = try ASN1Parser.parseOne(from: data)

        guard value.tag.isSequence else {
            throw X509Error.invalidExtension(oid: "subjectAltName", reason: "Must be SEQUENCE")
        }

        var dnsNames: [String] = []
        var emailAddresses: [String] = []
        var uris: [String] = []
        var ipAddresses: [Data] = []

        for child in value.children {
            guard child.tag.tagClass == .contextSpecific else { continue }

            switch child.tag.tagNumber {
            case 1: // rfc822Name
                if let str = String(data: child.content, encoding: .ascii) {
                    emailAddresses.append(str)
                }
            case 2: // dNSName
                if let str = String(data: child.content, encoding: .ascii) {
                    dnsNames.append(str)
                }
            case 6: // uniformResourceIdentifier
                if let str = String(data: child.content, encoding: .ascii) {
                    uris.append(str)
                }
            case 7: // iPAddress
                ipAddresses.append(child.content)
            default:
                // Skip other types
                break
            }
        }

        return SubjectAltName(
            dnsNames: dnsNames,
            emailAddresses: emailAddresses,
            uris: uris,
            ipAddresses: ipAddresses
        )
    }

    /// All hostnames (DNS names)
    public var allHostnames: [String] {
        dnsNames
    }
}

// MARK: - Authority Key Identifier

/// Authority Key Identifier extension (RFC 5280 Section 4.2.1.1)
///
/// ```
/// AuthorityKeyIdentifier ::= SEQUENCE {
///     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
///     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
///     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
/// ```
public struct AuthorityKeyIdentifier: Sendable {
    /// Key identifier
    public let keyIdentifier: Data?

    public static func parse(from data: Data) throws -> AuthorityKeyIdentifier {
        let value = try ASN1Parser.parseOne(from: data)

        guard value.tag.isSequence else {
            throw X509Error.invalidExtension(oid: "authorityKeyIdentifier", reason: "Must be SEQUENCE")
        }

        var keyIdentifier: Data? = nil

        for child in value.children {
            if child.tag.tagClass == .contextSpecific && child.tag.tagNumber == 0 {
                keyIdentifier = child.content
                break
            }
        }

        return AuthorityKeyIdentifier(keyIdentifier: keyIdentifier)
    }
}
