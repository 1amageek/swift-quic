// QUICEngineConfigurationStrategy.swift
// Builds the injected crypto/cert capability for `QUICConnectionEngine` — the
// CSPRNG (`randomBytes`) and the fail-closed peer-certificate validator
// (`validateCertificate`) — with HOST and EMBEDDED strategies behind a single
// shared signature, mirroring the proven swift-tls split
// (`TLSConfigurationBridge` host / `TLSEngineEmbeddedStrategy` Embedded).
//
// The gate is `hasFeature(Embedded)`, NOT `canImport(Foundation)` (Foundation is
// importable under Embedded). Each branch provides the SAME function so the
// facade calls it with no `#if`:
//
//   * HOST: `randomBytes` over `SystemRandomNumberGenerator`; `validateCertificate`
//     delegates to the caller-injected X.509 validator (or, when none is given,
//     fails closed if a chain is presented). X.509 parsing stays in the host
//     `QUICCrypto`/swift-certificates layer — only DER bytes cross into the engine.
//   * EMBEDDED: `randomBytes` over the same stdlib CSPRNG idiom; `validateCertificate`
//     resolves the peer's raw public key from the leaf SubjectPublicKeyInfo
//     (RFC 7250) via `P2PCoreDER`, FAIL-CLOSED — an unparseable leaf (e.g. a full
//     X.509 certificate Embedded cannot parse) yields a rejection. No
//     swift-certificates, no X.509 types.
//
// A cross-type error mapping lives in a NAMED function, never a closure literal
// (Embedded binds `any Error` inside a closure `catch`).

import QUICWire
import QUICConnectionCore
import QUICConnectionEngineCore
import P2PCoreCrypto

#if hasFeature(Embedded)
import P2PCoreDER
#endif

/// A caller-supplied peer-trust decision over the raw DER chain. Returns an opaque
/// peer identifier (e.g. a libp2p PeerID) on success; THROWS to reject
/// (fail-closed). Only DER bytes cross the boundary — no X.509 types.
public typealias QUICPeerValidator = @Sendable (_ certificateChainDER: [[UInt8]]) throws(QUICEngineError) -> [UInt8]?

/// Builds the engine's injected crypto/cert closures for a connection.
///
/// This is the single place the facade fills `QUICConnectionEngineConfiguration`'s
/// capability seam; the host and Embedded strategies differ only in how
/// `validateCertificate` resolves peer trust (X.509 vs RPK), behind one signature.
public enum QUICEngineCapability {
    /// A cryptographically-random byte source for CIDs / PATH_CHALLENGE data, etc.
    public static func randomBytes(_ count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(count)
        var generator = SystemRandomNumberGenerator()
        var remaining = count
        while remaining > 0 {
            var word = generator.next()
            let take = min(remaining, 8)
            for _ in 0..<take {
                bytes.append(UInt8(truncatingIfNeeded: word))
                word >>= 8
            }
            remaining -= take
        }
        return bytes
    }

    /// The default peer-certificate validator for the current build.
    ///
    /// HOST: when the caller injects a validator it is used as-is; otherwise a
    /// presented chain is rejected (fail-closed — no silent accept of an
    /// unvalidated peer). EMBEDDED: the RPK validator resolves the leaf SPKI and
    /// rejects an unparseable / unsupported key (fail-closed), then defers the
    /// identity decision to the injected validator if present.
    public static func validateCertificate(
        injected: QUICPeerValidator?
    ) -> QUICPeerValidator {
        #if hasFeature(Embedded)
        return { (chain: [[UInt8]]) throws(QUICEngineError) -> [UInt8]? in
            try EmbeddedRPKStrategy.validate(chain: chain, injected: injected)
        }
        #else
        return { (chain: [[UInt8]]) throws(QUICEngineError) -> [UInt8]? in
            try HostCertStrategy.validate(chain: chain, injected: injected)
        }
        #endif
    }
}

#if !hasFeature(Embedded)

/// The host peer-trust strategy. X.509 verification proper lives in the host
/// `QUICCrypto`/swift-certificates layer (reached through the injected validator);
/// this only enforces fail-closed behaviour when no validator is supplied.
enum HostCertStrategy {
    static func validate(
        chain: [[UInt8]],
        injected: QUICPeerValidator?
    ) throws(QUICEngineError) -> [UInt8]? {
        guard let injected else {
            // A peer presented a chain but no validator was configured: do NOT
            // admit an unauthenticated peer (no silent fallback, RFC 9001).
            if chain.isEmpty { return nil }
            throw .cryptoClosureFailed("no certificate validator configured for a presented chain")
        }
        return try injected(chain)
    }
}

#else

/// The Embedded raw-public-key (RFC 7250) peer-trust strategy: resolve the peer's
/// public key from the leaf SubjectPublicKeyInfo, FAIL-CLOSED. An unparseable leaf
/// (e.g. a full X.509 certificate, which Embedded cannot parse) is rejected.
enum EmbeddedRPKStrategy {
    static func validate(
        chain: [[UInt8]],
        injected: QUICPeerValidator?
    ) throws(QUICEngineError) -> [UInt8]? {
        guard let leaf = chain.first else { return nil }
        // Resolve the raw public key; an unparseable SPKI is a hard reject.
        do {
            _ = try SubjectPublicKeyInfoDER.parse(leaf)
        } catch {
            throw .cryptoClosureFailed("peer leaf SubjectPublicKeyInfo is not a supported raw public key")
        }
        // The key parsed: defer the identity decision (e.g. libp2p PeerID match)
        // to the injected validator if present; otherwise surface no identity.
        guard let injected else { return nil }
        return try injected(chain)
    }
}

#endif
