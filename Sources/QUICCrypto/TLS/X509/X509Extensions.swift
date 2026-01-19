/// X.509 Certificate Extensions (RFC 5280 Section 4.2)
///
/// This file provides convenience extensions for working with X.509 certificate extensions
/// using the swift-certificates library.

import Foundation
@preconcurrency import X509
import SwiftASN1

// MARK: - Extension Helpers for X509Certificate

extension X509Certificate {
    /// Gets the basic constraints extension
    public var basicConstraints: BasicConstraints? {
        try? certificate.extensions.basicConstraints
    }

    /// Gets the key usage extension
    public var keyUsage: X509.KeyUsage? {
        try? certificate.extensions.keyUsage
    }

    /// Gets the extended key usage extension
    public var extendedKeyUsage: ExtendedKeyUsage? {
        try? certificate.extensions.extendedKeyUsage
    }

    /// Gets the subject alternative names extension
    public var subjectAlternativeNames: SubjectAlternativeNames? {
        try? certificate.extensions.subjectAlternativeNames
    }

    /// Gets the authority key identifier extension
    public var authorityKeyIdentifier: AuthorityKeyIdentifier? {
        try? certificate.extensions.authorityKeyIdentifier
    }

    /// Gets the subject key identifier extension
    public var subjectKeyIdentifier: SubjectKeyIdentifier? {
        try? certificate.extensions.subjectKeyIdentifier
    }

    /// Gets the name constraints extension
    public var nameConstraints: X509.NameConstraints? {
        try? certificate.extensions.nameConstraints
    }
}

// MARK: - BasicConstraints Helpers

extension BasicConstraints {
    /// Whether this certificate is a CA
    public var isCA: Bool {
        switch self {
        case .isCertificateAuthority:
            return true
        case .notCertificateAuthority:
            return false
        }
    }

    /// Maximum path length constraint
    public var pathLenConstraint: Int? {
        switch self {
        case .isCertificateAuthority(let maxPathLength):
            return maxPathLength
        case .notCertificateAuthority:
            return nil
        }
    }
}

// MARK: - KeyUsage is already an OptionSet with properties like digitalSignature, keyCertSign, etc.

// MARK: - ExtendedKeyUsage Helpers

extension ExtendedKeyUsage {
    /// Checks if this EKU includes server authentication
    public var isServerAuth: Bool {
        contains(.serverAuth)
    }

    /// Checks if this EKU includes client authentication
    public var isClientAuth: Bool {
        contains(.clientAuth)
    }
}

// MARK: - SubjectAlternativeNames Helpers

extension SubjectAlternativeNames {
    /// Gets all DNS names from the SAN extension
    public var dnsNames: [String] {
        compactMap { name in
            switch name {
            case .dnsName(let dns):
                return dns
            default:
                return nil
            }
        }
    }

    /// Gets all email addresses from the SAN extension
    public var emailAddresses: [String] {
        compactMap { name in
            switch name {
            case .rfc822Name(let email):
                return email
            default:
                return nil
            }
        }
    }

    /// Gets all URIs from the SAN extension
    public var uris: [String] {
        compactMap { name in
            switch name {
            case .uniformResourceIdentifier(let uri):
                return uri
            default:
                return nil
            }
        }
    }
}

// MARK: - NameConstraints Helpers

extension X509.NameConstraints {
    /// Check if name constraints are empty
    public var isEmpty: Bool {
        permittedDNSDomains.isEmpty &&
        excludedDNSDomains.isEmpty &&
        permittedEmailAddresses.isEmpty &&
        excludedEmailAddresses.isEmpty &&
        permittedIPRanges.isEmpty &&
        excludedIPRanges.isEmpty &&
        permittedURIDomains.isEmpty &&
        forbiddenURIDomains.isEmpty
    }
}
