/// TLS 1.3 Pre-Shared Key — adapter-side crypto/Date helpers.
///
/// The wire types (`PskIdentity`, `OfferedPsks`, `SelectedPsk`,
/// `PreSharedKeyExtension`) now live in the Embedded-clean `QUICTLSCore` and are
/// re-exported via `HandshakeMessage.swift`. This file keeps the crypto-bearing
/// `PSKBinderHelper` (SHA/HKDF/HMAC) and the `Date`-dependent
/// `PskIdentity(ticket:at:)` convenience, which require Foundation/Crypto.

import Foundation
import QUICTLSCore
import Crypto

// MARK: - PSK Identity (ticket convenience)

extension PskIdentity {
    /// Create from a session ticket (Date-dependent; adapter-only).
    public init(ticket: SessionTicketData, at now: Date = Date()) {
        self.init(identity: [UInt8](ticket.ticket), obfuscatedTicketAge: ticket.obfuscatedAge(at: now))
    }
}

// MARK: - PSK Binder Computation

/// Helper for computing PSK binders
public struct PSKBinderHelper: Sendable {
    /// The cipher suite (determines hash function)
    public let cipherSuite: CipherSuite

    public init(cipherSuite: CipherSuite = .tls_aes_128_gcm_sha256) {
        self.cipherSuite = cipherSuite
    }

    /// Derive the binder key from early secret
    /// - Parameters:
    ///   - earlySecret: The early secret derived from PSK
    ///   - isResumption: true for resumption PSK, false for external PSK
    /// - Returns: The binder key
    public func binderKey(
        from earlySecret: Data,
        isResumption: Bool
    ) -> Data {
        let label = isResumption ? "res binder" : "ext binder"
        let emptyHash = emptyTranscriptHash()

        return deriveSecret(
            secret: earlySecret,
            label: label,
            transcriptHash: emptyHash
        )
    }

    /// Compute the binder value
    /// - Parameters:
    ///   - key: The binder key
    ///   - transcriptHash: Hash of ClientHello up to (but not including) binders
    /// - Returns: The binder value
    public func binder(
        forKey key: Data,
        transcriptHash: Data
    ) -> Data {
        // finished_key = HKDF-Expand-Label(binder_key, "finished", "", Hash.length)
        let finishedKey = hkdfExpandLabel(
            secret: key,
            label: "finished",
            context: Data(),
            length: hashLength
        )

        // binder = HMAC(finished_key, Transcript-Hash(Truncate(ClientHello)))
        return hmac(key: finishedKey, data: transcriptHash)
    }

    /// Verify a binder
    public func isValidBinder(
        forKey key: Data,
        transcriptHash: Data,
        expected: Data
    ) -> Bool {
        let computed = binder(forKey: key, transcriptHash: transcriptHash)
        return constantTimeCompare(computed, expected)
    }

    // MARK: - Private Helpers

    private var hashLength: Int {
        cipherSuite.hashLength
    }

    private func emptyTranscriptHash() -> Data {
        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            return Data(Crypto.SHA384.hash(data: Data()))
        default:
            return Data(Crypto.SHA256.hash(data: Data()))
        }
    }

    private func deriveSecret(secret: Data, label: String, transcriptHash: Data) -> Data {
        hkdfExpandLabel(secret: secret, label: label, context: transcriptHash, length: hashLength)
    }

    private func hkdfExpandLabel(secret: Data, label: String, context: Data, length: Int) -> Data {
        let fullLabel = "tls13 " + label
        let labelBytes = Data(fullLabel.utf8)

        var hkdfLabel = Data()
        hkdfLabel.append(UInt8(length >> 8))
        hkdfLabel.append(UInt8(length & 0xFF))
        hkdfLabel.append(UInt8(labelBytes.count))
        hkdfLabel.append(labelBytes)
        hkdfLabel.append(UInt8(context.count))
        hkdfLabel.append(context)

        let key = SymmetricKey(data: secret)

        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            let output = HKDF<SHA384>.expand(
                pseudoRandomKey: key,
                info: hkdfLabel,
                outputByteCount: length
            )
            return output.withUnsafeBytes { Data($0) }
        default:
            let output = HKDF<SHA256>.expand(
                pseudoRandomKey: key,
                info: hkdfLabel,
                outputByteCount: length
            )
            return output.withUnsafeBytes { Data($0) }
        }
    }

    private func hmac(key: Data, data: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)

        switch cipherSuite {
        case .tls_aes_256_gcm_sha384:
            let mac = HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey)
            return Data(mac)
        default:
            let mac = HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey)
            return Data(mac)
        }
    }

    private func constantTimeCompare(_ a: Data, _ b: Data) -> Bool {
        guard a.count == b.count else { return false }
        var result: UInt8 = 0
        for i in 0..<a.count {
            result |= a[a.startIndex + i] ^ b[b.startIndex + i]
        }
        return result == 0
    }
}
