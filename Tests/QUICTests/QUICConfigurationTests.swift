import Testing
import Foundation
@testable import QUIC
@testable import QUICCore

@Suite("QUIC Configuration Tests")
struct QUICConfigurationTests {

    @Test("Default configuration")
    func defaultConfig() {
        let config = QUICConfiguration()

        #expect(config.maxIdleTimeout == .seconds(30))
        #expect(config.maxUDPPayloadSize == 1200)
        #expect(config.initialMaxData == 10_000_000)
        #expect(config.initialMaxStreamsBidi == 100)
        #expect(config.alpn == ["h3"])
    }

    @Test("libp2p configuration")
    func libp2pConfig() {
        let config = QUICConfiguration.libp2p()

        #expect(config.alpn == ["libp2p"])
    }

    @Test("Transport parameters from configuration")
    func transportParameters() {
        let config = QUICConfiguration()
        let scid = ConnectionID.random(length: 8)

        let params = TransportParameters(from: config, sourceConnectionID: scid)

        #expect(params.initialMaxData == config.initialMaxData)
        #expect(params.initialMaxStreamsBidi == config.initialMaxStreamsBidi)
        #expect(params.initialSourceConnectionID == scid)
    }
}
