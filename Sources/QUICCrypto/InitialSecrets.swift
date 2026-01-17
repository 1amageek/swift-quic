/// QUIC Initial Secrets Derivation (RFC 9001 Section 5.2)
///
/// Initial packets are encrypted using keys derived from the
/// Destination Connection ID and a version-specific salt.

import Foundation
import Crypto
import QUICCore

// MARK: - Initial Secrets

/// Derives initial secrets from a connection ID
public struct InitialSecrets: Sendable {
    /// Client initial secret
    public let clientSecret: SymmetricKey

    /// Server initial secret
    public let serverSecret: SymmetricKey

    /// Derives initial secrets for the given connection ID and version
    /// - Parameters:
    ///   - connectionID: The Destination Connection ID from the first Initial packet
    ///   - version: The QUIC version
    /// - Returns: The derived initial secrets
    public static func derive(
        connectionID: ConnectionID,
        version: QUICVersion
    ) throws -> InitialSecrets {
        guard let salt = version.initialSalt else {
            throw QUICError.unsupportedVersion(version.rawValue)
        }

        // Extract initial secret using HKDF
        // initial_secret = HKDF-Extract(initial_salt, cid)
        let initialSecret = deriveInitialSecret(connectionID: connectionID, salt: salt)

        // Derive client and server secrets
        // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
        // server_initial_secret = HKDF-Expand-Label(initial_secret, "server in", "", 32)
        let clientSecret = try hkdfExpandLabel(
            secret: initialSecret,
            label: "client in",
            context: Data(),
            length: 32
        )

        let serverSecret = try hkdfExpandLabel(
            secret: initialSecret,
            label: "server in",
            context: Data(),
            length: 32
        )

        return InitialSecrets(
            clientSecret: SymmetricKey(data: clientSecret),
            serverSecret: SymmetricKey(data: serverSecret)
        )
    }

    private static func deriveInitialSecret(connectionID: ConnectionID, salt: Data) -> SymmetricKey {
        // HKDF-Extract with salt and connection ID
        let prk = HKDF<SHA256>.extract(
            inputKeyMaterial: SymmetricKey(data: connectionID.bytes),
            salt: salt
        )
        // Convert HashedAuthenticationCode to SymmetricKey
        return SymmetricKey(data: prk)
    }
}

// MARK: - Key Material

/// Cryptographic key material derived from a secret
public struct KeyMaterial: Sendable {
    /// The packet protection key
    public let key: SymmetricKey

    /// The packet protection IV
    public let iv: Data

    /// The header protection key
    public let hp: SymmetricKey

    /// Derives key material from a secret
    /// - Parameter secret: The secret to derive from
    /// - Returns: The derived key material
    public static func derive(from secret: SymmetricKey) throws -> KeyMaterial {
        // For AES-128-GCM:
        // key = HKDF-Expand-Label(secret, "quic key", "", 16)
        // iv = HKDF-Expand-Label(secret, "quic iv", "", 12)
        // hp = HKDF-Expand-Label(secret, "quic hp", "", 16)

        let key = try hkdfExpandLabel(
            secret: secret,
            label: "quic key",
            context: Data(),
            length: 16
        )

        let iv = try hkdfExpandLabel(
            secret: secret,
            label: "quic iv",
            context: Data(),
            length: 12
        )

        let hp = try hkdfExpandLabel(
            secret: secret,
            label: "quic hp",
            context: Data(),
            length: 16
        )

        return KeyMaterial(
            key: SymmetricKey(data: key),
            iv: iv,
            hp: SymmetricKey(data: hp)
        )
    }
}

// MARK: - HKDF-Expand-Label

/// HKDF-Expand-Label as defined in TLS 1.3 (RFC 8446 Section 7.1)
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HkdfLabel is:
///     struct {
///         uint16 length = Length;
///         opaque label<7..255> = "tls13 " + Label;
///         opaque context<0..255> = Context;
///     } HkdfLabel;
func hkdfExpandLabel(
    secret: SymmetricKey,
    label: String,
    context: Data,
    length: Int
) throws -> Data {
    // Build HkdfLabel structure
    let fullLabel = "tls13 " + label
    let labelBytes = Data(fullLabel.utf8)

    var hkdfLabel = Data()

    // uint16 length
    hkdfLabel.append(UInt8(length >> 8))
    hkdfLabel.append(UInt8(length & 0xFF))

    // opaque label<7..255>
    hkdfLabel.append(UInt8(labelBytes.count))
    hkdfLabel.append(labelBytes)

    // opaque context<0..255>
    hkdfLabel.append(UInt8(context.count))
    hkdfLabel.append(context)

    // HKDF-Expand
    let output = HKDF<SHA256>.expand(
        pseudoRandomKey: secret,
        info: hkdfLabel,
        outputByteCount: length
    )

    return output.withUnsafeBytes { Data($0) }
}
