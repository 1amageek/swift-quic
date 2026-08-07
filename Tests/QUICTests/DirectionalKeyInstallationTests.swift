import Crypto
import Foundation
import Testing
@testable import QUIC
@testable import QUICCore
@testable import QUICCrypto

@Suite("Directional TLS Key Installation")
struct DirectionalKeyInstallationTests {
    private let clientSecret = SymmetricKey(data: Data(repeating: 0x31, count: 32))
    private let serverSecret = SymmetricKey(data: Data(repeating: 0x53, count: 32))

    @Test("Client installs independently exported read and write secrets")
    func clientInstallsDirectionalSecrets() throws {
        let processor = PacketProcessor()

        try processor.installKeys(
            KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: nil
            ),
            isClient: true
        )

        let writeOnly = try #require(processor.context(for: .handshake))
        #expect(writeOnly.opener == nil)
        #expect(writeOnly.sealer != nil)

        try processor.installKeys(
            KeysAvailableInfo(
                level: .handshake,
                clientSecret: nil,
                serverSecret: serverSecret
            ),
            isClient: true
        )

        let bidirectional = try #require(processor.context(for: .handshake))
        #expect(bidirectional.opener != nil)
        #expect(bidirectional.sealer != nil)
    }

    @Test("Server installs independently exported read and write secrets")
    func serverInstallsDirectionalSecrets() throws {
        let processor = PacketProcessor()

        try processor.installKeys(
            KeysAvailableInfo(
                level: .handshake,
                clientSecret: clientSecret,
                serverSecret: nil
            ),
            isClient: false
        )

        let readOnly = try #require(processor.context(for: .handshake))
        #expect(readOnly.opener != nil)
        #expect(readOnly.sealer == nil)

        try processor.installKeys(
            KeysAvailableInfo(
                level: .handshake,
                clientSecret: nil,
                serverSecret: serverSecret
            ),
            isClient: false
        )

        let bidirectional = try #require(processor.context(for: .handshake))
        #expect(bidirectional.opener != nil)
        #expect(bidirectional.sealer != nil)
    }

    @Test("Application key phase waits for both directions")
    func applicationKeyPhaseWaitsForBothDirections() throws {
        let processor = PacketProcessor()

        try processor.installKeys(
            KeysAvailableInfo(
                level: .application,
                clientSecret: clientSecret,
                serverSecret: nil
            ),
            isClient: true
        )
        #expect(!processor.isKeyUpdateWired)

        try processor.installKeys(
            KeysAvailableInfo(
                level: .application,
                clientSecret: nil,
                serverSecret: serverSecret
            ),
            isClient: true
        )
        #expect(processor.isKeyUpdateWired)
        #expect(processor.currentApplicationKeyPhase == 0)
    }

    @Test("Missing directional secrets is rejected")
    func missingDirectionalSecretsIsRejected() {
        let processor = PacketProcessor()

        #expect(throws: PacketCodecError.self) {
            try processor.installKeys(
                KeysAvailableInfo(
                    level: .handshake,
                    clientSecret: nil,
                    serverSecret: nil
                ),
                isClient: true
            )
        }
    }
}
