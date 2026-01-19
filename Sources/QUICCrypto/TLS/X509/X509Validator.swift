/// X.509 Certificate Validation (RFC 5280 Section 6)
///
/// Validates certificate chains according to X.509 path validation rules.

import Foundation
import Crypto

// MARK: - Validation Options

/// Options for X.509 certificate validation
public struct X509ValidationOptions: Sendable {
    /// Whether to check certificate validity periods
    public var checkValidity: Bool

    /// Whether to check BasicConstraints for CA certificates
    public var checkBasicConstraints: Bool

    /// Whether to check KeyUsage extensions
    public var checkKeyUsage: Bool

    /// Whether to check Extended Key Usage extensions
    public var checkExtendedKeyUsage: Bool

    /// Required Extended Key Usage for the leaf certificate
    /// If set, the certificate must contain this EKU (or anyExtendedKeyUsage)
    public var requiredEKU: RequiredEKU?

    /// Whether to validate SAN format (DNS names, IP addresses)
    public var validateSANFormat: Bool

    /// Whether to check Name Constraints from CA certificates
    public var checkNameConstraints: Bool

    /// Hostname to verify against SubjectAltName/CN
    public var hostname: String?

    /// Time at which to validate (defaults to current time)
    public var validationTime: Date

    /// Whether to allow self-signed certificates without trusted root
    public var allowSelfSigned: Bool

    /// Maximum chain depth (not including leaf)
    public var maxChainDepth: Int

    /// Creates default validation options
    public init(
        checkValidity: Bool = true,
        checkBasicConstraints: Bool = true,
        checkKeyUsage: Bool = true,
        checkExtendedKeyUsage: Bool = true,
        requiredEKU: RequiredEKU? = nil,
        validateSANFormat: Bool = true,
        checkNameConstraints: Bool = true,
        hostname: String? = nil,
        validationTime: Date = Date(),
        allowSelfSigned: Bool = false,
        maxChainDepth: Int = 10
    ) {
        self.checkValidity = checkValidity
        self.checkBasicConstraints = checkBasicConstraints
        self.checkKeyUsage = checkKeyUsage
        self.checkExtendedKeyUsage = checkExtendedKeyUsage
        self.requiredEKU = requiredEKU
        self.validateSANFormat = validateSANFormat
        self.checkNameConstraints = checkNameConstraints
        self.hostname = hostname
        self.validationTime = validationTime
        self.allowSelfSigned = allowSelfSigned
        self.maxChainDepth = maxChainDepth
    }
}

/// Required Extended Key Usage type
public enum RequiredEKU: Sendable {
    case serverAuth
    case clientAuth
    case codeSigning
    case emailProtection
    case timeStamping
    case ocspSigning

    /// OID for this EKU
    public var oid: String {
        switch self {
        case .serverAuth: return "1.3.6.1.5.5.7.3.1"
        case .clientAuth: return "1.3.6.1.5.5.7.3.2"
        case .codeSigning: return "1.3.6.1.5.5.7.3.3"
        case .emailProtection: return "1.3.6.1.5.5.7.3.4"
        case .timeStamping: return "1.3.6.1.5.5.7.3.8"
        case .ocspSigning: return "1.3.6.1.5.5.7.3.9"
        }
    }

    /// anyExtendedKeyUsage OID (2.5.29.37.0)
    public static let anyExtendedKeyUsageOID = "2.5.29.37.0"
}

// MARK: - X.509 Validator

/// Validates X.509 certificate chains
public struct X509Validator: Sendable {
    /// Trusted root CA certificates
    private let trustedRoots: [X509Certificate]

    /// Validation options
    private let options: X509ValidationOptions

    /// Creates a validator with trusted roots and options
    public init(
        trustedRoots: [X509Certificate] = [],
        options: X509ValidationOptions = X509ValidationOptions()
    ) {
        self.trustedRoots = trustedRoots
        self.options = options
    }

    // MARK: - Public API

    /// Validates a certificate chain
    /// - Parameters:
    ///   - certificate: The end-entity (leaf) certificate
    ///   - intermediates: Intermediate CA certificates
    /// - Throws: X509Error if validation fails
    public func validate(
        certificate: X509Certificate,
        intermediates: [X509Certificate] = []
    ) throws {
        // Build the certificate chain
        let chain = try buildChain(leaf: certificate, intermediates: intermediates)

        // Check chain depth
        guard chain.count <= options.maxChainDepth + 1 else {
            throw X509Error.pathLengthExceeded(allowed: options.maxChainDepth, actual: chain.count - 1)
        }

        // Validate each certificate in the chain
        for (index, cert) in chain.enumerated() {
            let isCA = index > 0  // Everything except leaf is a CA
            try validateCertificate(cert, isCA: isCA, depth: index)
        }

        // Verify signatures in the chain
        try verifyChainSignatures(chain)

        // Verify Name Constraints from CA certificates (RFC 5280 Section 4.2.1.10)
        if options.checkNameConstraints {
            try verifyNameConstraints(chain)
        }

        // Verify the root is trusted
        try verifyTrust(chain: chain)

        // Verify hostname if specified
        if let hostname = options.hostname {
            try verifyHostname(certificate, hostname: hostname)
        }

        // Verify Extended Key Usage if required
        if options.checkExtendedKeyUsage {
            try verifyExtendedKeyUsage(certificate)
        }

        // Validate SAN format
        if options.validateSANFormat {
            try validateSANFormat(certificate)
        }
    }

    /// Validates a single certificate (without chain validation)
    public func validateSingle(_ certificate: X509Certificate) throws {
        try validateCertificate(certificate, isCA: false, depth: 0)

        if let hostname = options.hostname {
            try verifyHostname(certificate, hostname: hostname)
        }

        // Verify Extended Key Usage if required
        if options.checkExtendedKeyUsage {
            try verifyExtendedKeyUsage(certificate)
        }

        // Validate SAN format
        if options.validateSANFormat {
            try validateSANFormat(certificate)
        }
    }

    // MARK: - Chain Building

    /// Builds a certificate chain from leaf to root
    private func buildChain(
        leaf: X509Certificate,
        intermediates: [X509Certificate]
    ) throws -> [X509Certificate] {
        var chain: [X509Certificate] = [leaf]
        var current = leaf

        // Build chain by finding issuers
        while !current.isSelfSigned {
            // Look for issuer in intermediates
            guard let issuer = findIssuer(for: current, in: intermediates + trustedRoots) else {
                // If we can't find the issuer but have trusted roots, check if current is trusted
                if trustedRoots.contains(where: { $0.subject == current.subject }) {
                    break
                }
                throw X509Error.issuerNotFound(issuer: current.issuer.string)
            }

            // Prevent cycles
            if chain.contains(where: { $0.subject == issuer.subject && $0.serialNumber == issuer.serialNumber }) {
                break
            }

            chain.append(issuer)
            current = issuer

            // Safety limit
            if chain.count > options.maxChainDepth + 1 {
                break
            }
        }

        return chain
    }

    /// Finds the issuer certificate for a given certificate
    private func findIssuer(
        for certificate: X509Certificate,
        in candidates: [X509Certificate]
    ) -> X509Certificate? {
        for candidate in candidates {
            // Issuer's subject must match certificate's issuer
            if candidate.subject == certificate.issuer {
                return candidate
            }
        }
        return nil
    }

    // MARK: - Individual Certificate Validation

    /// Validates a single certificate
    private func validateCertificate(
        _ cert: X509Certificate,
        isCA: Bool,
        depth: Int
    ) throws {
        // Check validity period
        if options.checkValidity {
            if options.validationTime < cert.validity.notBefore {
                throw X509Error.certificateNotYetValid(notBefore: cert.validity.notBefore)
            }
            if options.validationTime > cert.validity.notAfter {
                throw X509Error.certificateExpired(notAfter: cert.validity.notAfter)
            }
        }

        // Check BasicConstraints for CA certificates
        if options.checkBasicConstraints && isCA {
            guard let bc = cert.extensions.basicConstraints else {
                // CA certificate must have BasicConstraints
                throw X509Error.notCA
            }
            guard bc.isCA else {
                throw X509Error.notCA
            }

            // Check path length constraint
            if let pathLen = bc.pathLenConstraint {
                // depth is 0-indexed from leaf, pathLen limits intermediates below this CA
                let remainingDepth = depth - 1  // CAs below this one
                if remainingDepth > pathLen {
                    throw X509Error.pathLengthExceeded(allowed: pathLen, actual: remainingDepth)
                }
            }
        }

        // Check KeyUsage
        if options.checkKeyUsage {
            if let ku = cert.extensions.keyUsage {
                if isCA {
                    // CA must have keyCertSign
                    guard ku.contains(.keyCertSign) else {
                        throw X509Error.invalidKeyUsage("CA certificate missing keyCertSign")
                    }
                } else {
                    // Leaf certificate for TLS should have digitalSignature
                    guard ku.contains(.digitalSignature) else {
                        throw X509Error.invalidKeyUsage("Certificate missing digitalSignature")
                    }
                }
            }
        }
    }

    // MARK: - Signature Verification

    /// Verifies signatures in the certificate chain
    private func verifyChainSignatures(_ chain: [X509Certificate]) throws {
        // Verify each certificate is signed by its issuer
        for i in 0..<(chain.count - 1) {
            let cert = chain[i]
            let issuer = chain[i + 1]

            try verifySignature(of: cert, signedBy: issuer)
        }

        // Verify the root (last certificate) if it's self-signed
        if let root = chain.last, root.isSelfSigned {
            try verifySignature(of: root, signedBy: root)
        }
    }

    /// Verifies a certificate's signature
    private func verifySignature(
        of certificate: X509Certificate,
        signedBy issuer: X509Certificate
    ) throws {
        // Get issuer's public key
        let publicKey: VerificationKey
        do {
            publicKey = try issuer.extractPublicKey()
        } catch {
            throw X509Error.invalidPublicKey("Failed to extract issuer public key: \(error)")
        }

        // Determine signature scheme
        guard let scheme = certificate.signatureAlgorithm.signatureScheme else {
            throw X509Error.unsupportedSignatureAlgorithm(certificate.signatureAlgorithm.algorithm.dotNotation)
        }

        // Verify scheme matches key type
        guard scheme == publicKey.scheme else {
            throw X509Error.signatureAlgorithmMismatch
        }

        // Verify signature
        do {
            let valid = try publicKey.verify(
                signature: certificate.signatureValue,
                for: certificate.tbsCertificateBytes
            )
            guard valid else {
                throw X509Error.signatureVerificationFailed("Signature is invalid")
            }
        } catch let error as X509Error {
            throw error
        } catch {
            throw X509Error.signatureVerificationFailed(error.localizedDescription)
        }
    }

    // MARK: - Name Constraints Verification (RFC 5280 Section 4.2.1.10)

    /// Verifies Name Constraints from CA certificates in the chain
    ///
    /// For each CA with Name Constraints:
    /// - All certificates issued by that CA (and subsequent CAs) must have
    ///   names that satisfy the constraints
    /// - Names in permittedSubtrees are the only allowed names (if present)
    /// - Names in excludedSubtrees are forbidden
    private func verifyNameConstraints(_ chain: [X509Certificate]) throws {
        // Collect all name constraints from CA certificates (index > 0)
        // We apply each CA's constraints to all certificates below it in the chain
        for caIndex in 1..<chain.count {
            let ca = chain[caIndex]

            guard let constraints = ca.extensions.nameConstraints else {
                continue  // No constraints from this CA
            }

            if constraints.isEmpty {
                continue  // Empty constraints = no restrictions
            }

            // Apply these constraints to all certificates below this CA
            for certIndex in 0..<caIndex {
                let cert = chain[certIndex]
                try verifyNameAgainstConstraints(cert, constraints: constraints)
            }
        }
    }

    /// Verifies a certificate's names against Name Constraints
    private func verifyNameAgainstConstraints(
        _ certificate: X509Certificate,
        constraints: NameConstraints
    ) throws {
        // Collect all names from the certificate
        var dnsNames: [String] = []
        var emailAddresses: [String] = []
        var uris: [String] = []

        // Get names from SAN
        if let san = certificate.extensions.subjectAltName {
            dnsNames.append(contentsOf: san.dnsNames)
            emailAddresses.append(contentsOf: san.emailAddresses)
            uris.append(contentsOf: san.uris)
        }

        // Get Common Name from subject (treated as DNS name if no SAN DNS names)
        if let cn = certificate.subject.commonName, dnsNames.isEmpty {
            dnsNames.append(cn)
        }

        // Check DNS names
        for dnsName in dnsNames {
            try checkNameAgainstConstraints(
                name: .dnsName(dnsName),
                permitted: constraints.permittedSubtrees,
                excluded: constraints.excludedSubtrees
            )
        }

        // Check email addresses
        for email in emailAddresses {
            try checkNameAgainstConstraints(
                name: .rfc822Name(email),
                permitted: constraints.permittedSubtrees,
                excluded: constraints.excludedSubtrees
            )
        }

        // Check URIs
        for uri in uris {
            try checkNameAgainstConstraints(
                name: .uri(uri),
                permitted: constraints.permittedSubtrees,
                excluded: constraints.excludedSubtrees
            )
        }
    }

    /// Checks a single name against permitted and excluded subtrees
    private func checkNameAgainstConstraints(
        name: NameConstraints.GeneralName,
        permitted: [NameConstraints.GeneralSubtree],
        excluded: [NameConstraints.GeneralSubtree]
    ) throws {
        // First check excluded - if matched, reject
        for subtree in excluded {
            if nameMatches(name, subtree: subtree) {
                throw X509Error.nameConstraintsViolation(
                    name: nameDescription(name),
                    reason: "excluded by Name Constraints"
                )
            }
        }

        // If there are permitted subtrees for this name type, at least one must match
        let relevantPermitted = permitted.filter { sameNameType($0.base, as: name) }
        if !relevantPermitted.isEmpty {
            let matchesAny = relevantPermitted.contains { nameMatches(name, subtree: $0) }
            if !matchesAny {
                throw X509Error.nameConstraintsViolation(
                    name: nameDescription(name),
                    reason: "not within permitted Name Constraints"
                )
            }
        }
    }

    /// Checks if two GeneralNames are the same type
    private func sameNameType(_ a: NameConstraints.GeneralName, as b: NameConstraints.GeneralName) -> Bool {
        switch (a, b) {
        case (.dnsName, .dnsName): return true
        case (.rfc822Name, .rfc822Name): return true
        case (.uri, .uri): return true
        case (.ipAddress, .ipAddress): return true
        case (.directoryName, .directoryName): return true
        default: return false
        }
    }

    /// Checks if a name matches a subtree constraint
    private func nameMatches(_ name: NameConstraints.GeneralName, subtree: NameConstraints.GeneralSubtree) -> Bool {
        // minimum/maximum are rarely used in practice, we handle minimum=0 only
        guard subtree.minimum == 0 else { return false }

        switch (name, subtree.base) {
        case let (.dnsName(certName), .dnsName(constraintName)):
            return dnsNameMatches(certName, constraint: constraintName)

        case let (.rfc822Name(certEmail), .rfc822Name(constraintEmail)):
            return emailMatches(certEmail, constraint: constraintEmail)

        case let (.uri(certUri), .uri(constraintUri)):
            return uriMatches(certUri, constraint: constraintUri)

        case let (.ipAddress(certAddr, certMask), .ipAddress(constraintAddr, constraintMask)):
            return ipAddressMatches(
                address: certAddr,
                mask: certMask,
                constraintAddress: constraintAddr,
                constraintMask: constraintMask
            )

        default:
            return false
        }
    }

    /// DNS name matching for Name Constraints
    ///
    /// RFC 5280: A constraint ".example.com" matches "foo.example.com" and "example.com"
    /// but not "notexample.com"
    private func dnsNameMatches(_ name: String, constraint: String) -> Bool {
        let nameLower = name.lowercased()
        let constraintLower = constraint.lowercased()

        // Exact match
        if nameLower == constraintLower {
            return true
        }

        // If constraint starts with ".", it's a subdomain constraint
        if constraintLower.hasPrefix(".") {
            // name must end with the constraint
            if nameLower.hasSuffix(constraintLower) {
                return true
            }
            // or be exactly the domain without the leading dot
            let domain = String(constraintLower.dropFirst())
            if nameLower == domain {
                return true
            }
        } else {
            // Constraint without leading dot - name must be subdomain or exact match
            if nameLower.hasSuffix("." + constraintLower) {
                return true
            }
        }

        return false
    }

    /// Email address matching for Name Constraints
    ///
    /// RFC 5280: "@example.com" matches any email at example.com
    /// "example.com" matches any email at example.com or subdomains
    private func emailMatches(_ email: String, constraint: String) -> Bool {
        let emailLower = email.lowercased()
        let constraintLower = constraint.lowercased()

        // If constraint contains @, it must be exact local part match
        if constraintLower.contains("@") {
            return emailLower == constraintLower
        }

        // Otherwise constraint is a domain
        guard let atIndex = emailLower.firstIndex(of: "@") else {
            return false
        }

        let emailDomain = String(emailLower[emailLower.index(after: atIndex)...])
        return dnsNameMatches(emailDomain, constraint: constraintLower)
    }

    /// URI matching for Name Constraints
    private func uriMatches(_ uri: String, constraint: String) -> Bool {
        guard let uriURL = URL(string: uri),
              let host = uriURL.host else {
            return false
        }

        return dnsNameMatches(host, constraint: constraint)
    }

    /// IP address matching for Name Constraints
    ///
    /// Checks if the certificate's IP is within the constraint's subnet
    private func ipAddressMatches(
        address: Data,
        mask: Data,
        constraintAddress: Data,
        constraintMask: Data
    ) -> Bool {
        // Must be same address family
        guard address.count == constraintAddress.count else { return false }
        guard mask.count == constraintMask.count else { return false }
        guard address.count == mask.count else { return false }

        // Apply constraint mask and compare
        for i in 0..<address.count {
            let maskedAddr = address[address.startIndex.advanced(by: i)] & constraintMask[constraintMask.startIndex.advanced(by: i)]
            let maskedConstraint = constraintAddress[constraintAddress.startIndex.advanced(by: i)] & constraintMask[constraintMask.startIndex.advanced(by: i)]
            if maskedAddr != maskedConstraint {
                return false
            }
        }

        return true
    }

    /// Returns a human-readable description of a GeneralName
    private func nameDescription(_ name: NameConstraints.GeneralName) -> String {
        switch name {
        case .dnsName(let dns): return "DNS:\(dns)"
        case .rfc822Name(let email): return "email:\(email)"
        case .uri(let uri): return "URI:\(uri)"
        case .ipAddress(let addr, _): return "IP:\(addr.map { String(format: "%d", $0) }.joined(separator: "."))"
        case .directoryName: return "directoryName"
        case .unknown(let tag, _): return "unknown(\(tag))"
        }
    }

    // MARK: - Trust Verification

    /// Verifies that the chain leads to a trusted root
    private func verifyTrust(chain: [X509Certificate]) throws {
        guard let root = chain.last else {
            throw X509Error.emptyChain
        }

        // Check if root is in trusted roots
        let isTrusted = trustedRoots.contains { trusted in
            trusted.subject == root.subject &&
            trusted.subjectPublicKeyInfo.subjectPublicKey == root.subjectPublicKeyInfo.subjectPublicKey
        }

        if isTrusted {
            return
        }

        // If self-signed and allowSelfSigned is true, accept it
        if root.isSelfSigned && options.allowSelfSigned {
            return
        }

        // If it's a single self-signed certificate
        if chain.count == 1 && root.isSelfSigned {
            if options.allowSelfSigned {
                return
            }
            throw X509Error.selfSignedNotTrusted
        }

        throw X509Error.untrustedRoot
    }

    // MARK: - Hostname Verification

    /// Verifies the hostname matches the certificate
    private func verifyHostname(
        _ certificate: X509Certificate,
        hostname: String
    ) throws {
        var matchedNames: [String] = []

        // Check Subject Alternative Name first
        if let san = certificate.extensions.subjectAltName {
            for dnsName in san.dnsNames {
                matchedNames.append(dnsName)
                if matchHostname(pattern: dnsName, hostname: hostname) {
                    return
                }
            }
        }

        // Fall back to Common Name (deprecated but still used)
        if let cn = certificate.subject.commonName {
            matchedNames.append(cn)
            if matchHostname(pattern: cn, hostname: hostname) {
                return
            }
        }

        throw X509Error.hostnameMismatch(expected: hostname, actual: matchedNames)
    }

    /// Matches a hostname pattern against a hostname
    private func matchHostname(pattern: String, hostname: String) -> Bool {
        let patternLower = pattern.lowercased()
        let hostnameLower = hostname.lowercased()

        // Exact match
        if patternLower == hostnameLower {
            return true
        }

        // Wildcard matching (*.example.com)
        if patternLower.hasPrefix("*.") {
            let suffix = String(patternLower.dropFirst(2))  // Remove "*."
            let hostParts = hostnameLower.split(separator: ".")

            // Wildcard only matches one label
            if hostParts.count >= 2 {
                let hostSuffix = hostParts.dropFirst().joined(separator: ".")
                if hostSuffix == suffix {
                    return true
                }
            }
        }

        return false
    }

    // MARK: - Extended Key Usage Verification (RFC 5280 Section 4.2.1.12)

    /// Verifies Extended Key Usage of the certificate
    ///
    /// RFC 5280: If the extension is present, then the certificate MUST only
    /// be used for one of the purposes indicated. If multiple purposes are
    /// indicated the application need not recognize all purposes indicated,
    /// as long as the intended purpose is present.
    ///
    /// If a certificate contains both a key usage extension and an extended
    /// key usage extension, then both extensions MUST be processed independently
    /// and the certificate MUST only be used for a purpose consistent with both
    /// extensions.
    private func verifyExtendedKeyUsage(_ certificate: X509Certificate) throws {
        // If no required EKU is specified, skip validation
        guard let requiredEKU = options.requiredEKU else {
            return
        }

        // If EKU extension is not present, the certificate is valid for any purpose
        // RFC 5280: "If the extension is absent, all purposes are acceptable"
        guard let eku = certificate.extensions.extendedKeyUsage else {
            return
        }

        // Check if the required EKU is present
        let requiredOID = requiredEKU.oid
        let hasRequiredUsage = eku.keyPurposes.contains { $0.dotNotation == requiredOID }

        // Check for anyExtendedKeyUsage (2.5.29.37.0) which allows all purposes
        let hasAnyUsage = eku.keyPurposes.contains { $0.dotNotation == RequiredEKU.anyExtendedKeyUsageOID }

        if hasRequiredUsage || hasAnyUsage {
            return
        }

        throw X509Error.invalidExtendedKeyUsage(
            required: requiredOID,
            found: eku.keyPurposes.map { $0.dotNotation }
        )
    }

    // MARK: - SAN Format Validation

    /// Validates the format of Subject Alternative Name entries
    ///
    /// This ensures that SAN entries conform to their respective formats:
    /// - DNS names: RFC 1035 compliant labels
    /// - IP addresses: Valid IPv4 (4 bytes) or IPv6 (16 bytes)
    /// - URIs: Valid URL format
    private func validateSANFormat(_ certificate: X509Certificate) throws {
        guard let san = certificate.extensions.subjectAltName else {
            return
        }

        // Validate DNS names
        for dnsName in san.dnsNames {
            if !isValidDNSName(dnsName) {
                throw X509Error.malformedSAN(type: "dNSName", value: dnsName)
            }
        }

        // Validate IP addresses
        for ipData in san.ipAddresses {
            if !isValidIPAddressData(ipData) {
                throw X509Error.malformedSAN(
                    type: "iPAddress",
                    value: ipData.map { String(format: "%02x", $0) }.joined()
                )
            }
        }

        // Validate URIs
        for uri in san.uris {
            if !isValidURI(uri) {
                throw X509Error.malformedSAN(type: "uniformResourceIdentifier", value: uri)
            }
        }
    }

    /// Validates a DNS name according to RFC 1035
    ///
    /// Rules:
    /// - Maximum total length: 253 characters
    /// - Each label: 1-63 characters
    /// - Labels contain alphanumeric characters and hyphens
    /// - Labels cannot start or end with a hyphen
    /// - Wildcard (*) is only allowed as the leftmost label
    private func isValidDNSName(_ name: String) -> Bool {
        // Empty name is invalid
        guard !name.isEmpty else { return false }

        // Maximum length 253 characters
        guard name.count <= 253 else { return false }

        let labels = name.split(separator: ".", omittingEmptySubsequences: false).map { String($0) }

        // Must have at least one label
        guard !labels.isEmpty else { return false }

        for (index, label) in labels.enumerated() {
            // Each label must be 1-63 characters
            guard label.count >= 1 && label.count <= 63 else { return false }

            // Wildcard is only allowed as the leftmost label
            if label == "*" {
                guard index == 0 else { return false }
                continue
            }

            // Check first character: must be alphanumeric
            guard let first = label.first, first.isLetter || first.isNumber else {
                return false
            }

            // Check last character: must be alphanumeric
            guard let last = label.last, last.isLetter || last.isNumber else {
                return false
            }

            // Check all characters: alphanumeric or hyphen
            for char in label {
                guard char.isLetter || char.isNumber || char == "-" else {
                    return false
                }
            }
        }

        return true
    }

    /// Validates IP address data
    ///
    /// - IPv4: exactly 4 bytes
    /// - IPv6: exactly 16 bytes
    private func isValidIPAddressData(_ data: Data) -> Bool {
        return data.count == 4 || data.count == 16
    }

    /// Validates a URI format
    private func isValidURI(_ uri: String) -> Bool {
        guard let url = URL(string: uri) else {
            return false
        }
        // URI must have a scheme
        return url.scheme != nil
    }
}

// MARK: - Certificate Store

/// A store for trusted CA certificates
public struct CertificateStore: Sendable {
    /// The trusted certificates
    private var certificates: [X509Certificate]

    /// Creates an empty certificate store
    public init() {
        self.certificates = []
    }

    /// Creates a certificate store with initial certificates
    public init(certificates: [X509Certificate]) {
        self.certificates = certificates
    }

    /// Adds a certificate to the store
    public mutating func add(_ certificate: X509Certificate) {
        certificates.append(certificate)
    }

    /// Adds certificates from DER-encoded data
    public mutating func add(derEncoded data: Data) throws {
        let cert = try X509Certificate.parse(from: data)
        certificates.append(cert)
    }

    /// All certificates in the store
    public var all: [X509Certificate] {
        certificates
    }

    /// Creates a validator using this store as trusted roots
    public func validator(options: X509ValidationOptions = X509ValidationOptions()) -> X509Validator {
        X509Validator(trustedRoots: certificates, options: options)
    }
}
