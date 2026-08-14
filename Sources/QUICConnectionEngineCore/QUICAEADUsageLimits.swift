import QUICPacketProtectionCore

/// RFC 9001 section 6.6 packet limits. The stored policy is internal so an
/// application cannot accidentally weaken the protocol's security margin.
struct QUICAEADUsageLimits: Sendable {
    var aesGCMConfidentialityPackets: UInt64
    var aesGCMIntegrityFailures: UInt64
    var chaCha20IntegrityFailures: UInt64

    init(
        aesGCMConfidentialityPackets: UInt64 = 8_388_608,
        aesGCMIntegrityFailures: UInt64 = 4_503_599_627_370_496,
        chaCha20IntegrityFailures: UInt64 = 68_719_476_736
    ) {
        self.aesGCMConfidentialityPackets = aesGCMConfidentialityPackets
        self.aesGCMIntegrityFailures = aesGCMIntegrityFailures
        self.chaCha20IntegrityFailures = chaCha20IntegrityFailures
    }

    func confidentialityLimit(for suite: QUICProtectionSuite) -> UInt64 {
        switch suite {
        case .aes128GCM, .aes256GCM:
            return aesGCMConfidentialityPackets
        case .chaCha20Poly1305:
            // ChaCha20-Poly1305's confidentiality limit exceeds QUIC's entire
            // 2^62 packet-number space, so packet-number exhaustion is tighter.
            return UInt64.max
        }
    }

    func integrityLimit(for suite: QUICProtectionSuite) -> UInt64 {
        switch suite {
        case .aes128GCM, .aes256GCM:
            return aesGCMIntegrityFailures
        case .chaCha20Poly1305:
            return chaCha20IntegrityFailures
        }
    }
}
