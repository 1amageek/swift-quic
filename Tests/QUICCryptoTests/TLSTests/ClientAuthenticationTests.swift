/// QUIC TLS 1.3 client-side authentication tests
///
/// Verifies that a server cannot skip authentication: a Finished arriving before
/// the server's Certificate + CertificateVerify must be rejected. Previously the
/// client accepted Finished in `.waitCertificate`/`.waitCertificateVerify`, which
/// allowed an unauthenticated/MITM server to complete the handshake.

import Testing
import Foundation
@testable import QUICCore
@testable import QUICCrypto

@Suite("QUIC Client Authentication")
struct QUICClientAuthenticationTests {

    private static let testSigningKey = SigningKey.generateP256()
    private static let testCertificateChain = [Data([0x30, 0x82, 0x01, 0x00])]

    /// Split a buffer of concatenated TLS handshake messages into individual
    /// (type, full-message) pairs (4-byte header + content each).
    private func splitHandshakeMessages(_ data: Data) throws -> [(type: HandshakeType, message: Data)] {
        var result: [(HandshakeType, Data)] = []
        var buffer = data
        while buffer.count >= 4 {
            let (type, contentLength) = try HandshakeCodec.decodeHeader(from: buffer)
            let total = 4 + contentLength
            guard buffer.count >= total else { break }
            result.append((type, buffer.prefix(total)))
            buffer = Data(buffer.dropFirst(total))
        }
        return result
    }

    /// Drive a client + server through ClientHello/ServerHello and return:
    /// - the client (already advanced to wait-for-EncryptedExtensions)
    /// - the server's handshake-level flight split into messages.
    private func driveToServerFlight() async throws -> (
        client: TLS13Handler,
        serverHandshakeMessages: [(type: HandshakeType, message: Data)]
    ) {
        var clientConfig = TLSConfiguration.client(serverName: "localhost", alpnProtocols: ["h3"])
        clientConfig.expectedPeerPublicKey = Self.testSigningKey.publicKeyBytes
        let client = TLS13Handler(configuration: clientConfig)

        var serverConfig = TLSConfiguration()
        serverConfig.alpnProtocols = ["h3"]
        serverConfig.signingKey = Self.testSigningKey
        serverConfig.certificateChain = Self.testCertificateChain
        let server = TLS13Handler(configuration: serverConfig)

        let params = Data([0x04, 0x04, 0x00, 0x01, 0x00, 0x00])
        try client.setLocalTransportParameters(params)
        try server.setLocalTransportParameters(params)

        let clientOutputs = try await client.startHandshake(isClient: true)
        _ = try await server.startHandshake(isClient: false)

        var clientHello: Data?
        for output in clientOutputs {
            if case .handshakeData(let data, let level) = output, level == .initial {
                clientHello = data
            }
        }
        let ch = try #require(clientHello)

        let serverOutputs = try await server.processHandshakeData(ch, at: .initial)

        // Collect server output by level.
        var serverInitial = Data()
        var serverHandshake = Data()
        for output in serverOutputs {
            if case .handshakeData(let data, let level) = output {
                switch level {
                case .initial: serverInitial.append(data)
                case .handshake: serverHandshake.append(data)
                default: break
                }
            }
        }

        // Feed ServerHello (.initial) to the client → client awaits EncryptedExtensions.
        _ = try await client.processHandshakeData(serverInitial, at: .initial)

        let messages = try splitHandshakeMessages(serverHandshake)
        return (client, messages)
    }

    @Test("Client rejects server Finished that skips Certificate/CertificateVerify")
    func clientRejectsFinishedBeforeCertificate() async throws {
        let (client, messages) = try await driveToServerFlight()

        // Feed EncryptedExtensions only, then jump straight to Finished — skipping
        // the server's Certificate and CertificateVerify (the auth-skip attack).
        let ee = try #require(messages.first { $0.type == .encryptedExtensions })
        let finished = try #require(messages.first { $0.type == .finished })

        _ = try await client.processHandshakeData(ee.message, at: .handshake)

        await #expect(throws: (any Error).self) {
            _ = try await client.processHandshakeData(finished.message, at: .handshake)
        }
        #expect(!client.isHandshakeComplete)
    }

    @Test("Client completes when server presents Certificate + CertificateVerify + Finished")
    func clientCompletesWithFullServerFlight() async throws {
        let (client, messages) = try await driveToServerFlight()

        // Deliver the full server flight in order. This is the positive control:
        // the stricter Finished state guard must NOT break the real handshake.
        for msg in messages {
            _ = try await client.processHandshakeData(msg.message, at: .handshake)
        }
        #expect(client.isHandshakeComplete)
    }
}
