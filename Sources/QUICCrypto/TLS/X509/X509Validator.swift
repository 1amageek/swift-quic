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
        hostname: String? = nil,
        validationTime: Date = Date(),
        allowSelfSigned: Bool = false,
        maxChainDepth: Int = 10
    ) {
        self.checkValidity = checkValidity
        self.checkBasicConstraints = checkBasicConstraints
        self.checkKeyUsage = checkKeyUsage
        self.hostname = hostname
        self.validationTime = validationTime
        self.allowSelfSigned = allowSelfSigned
        self.maxChainDepth = maxChainDepth
    }
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

        // Verify the root is trusted
        try verifyTrust(chain: chain)

        // Verify hostname if specified
        if let hostname = options.hostname {
            try verifyHostname(certificate, hostname: hostname)
        }
    }

    /// Validates a single certificate (without chain validation)
    public func validateSingle(_ certificate: X509Certificate) throws {
        try validateCertificate(certificate, isCA: false, depth: 0)

        if let hostname = options.hostname {
            try verifyHostname(certificate, hostname: hostname)
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
