import Foundation
import Testing
@testable import QUIC
@testable import QUICCore

@Suite("Version Negotiator Validation Tests")
struct VersionNegotiatorValidationTests {
    @Test("Complete validation accepts a well-formed packet")
    func completeValidationSucceeds() throws {
        let fixture = try Fixture()
        let versions = [QUICVersion.v1, .v2]
        let packet = Self.packet(
            destinationCIDBytes: fixture.originalSCID.bytes,
            sourceCIDBytes: fixture.originalDCID.bytes,
            versions: versions
        )

        let offered = try VersionNegotiator.offeredVersions(
            inVersionNegotiationPacket: packet,
            originalDCID: fixture.originalDCID,
            originalSCID: fixture.originalSCID,
            attemptedVersion: fixture.attemptedVersion
        )

        #expect(offered == versions)
    }

    @Test(
        "Version list rejects each incomplete 32-bit suffix",
        arguments: [1, 2, 3]
    )
    func trailingVersionBytesAreRejected(trailingByteCount: Int) throws {
        let fixture = try Fixture()
        var packet = Self.packet(
            destinationCIDBytes: fixture.originalSCID.bytes,
            sourceCIDBytes: fixture.originalDCID.bytes,
            versions: [.v1]
        )
        packet.append(contentsOf: repeatElement(UInt8(0xA5), count: trailingByteCount))

        do {
            _ = try VersionNegotiator.parseVersions(from: packet)
            Issue.record("Expected an incomplete version suffix to be rejected")
        } catch {
            guard case .invalidPacketFormat(let reason) = error else {
                Issue.record("Expected invalidPacketFormat, received \(error)")
                return
            }
            #expect(reason.contains("multiple of 4"))
        }
    }

    @Test("Complete validation rejects a packet that advertises the attempted version")
    func attemptedVersionIsRejected() throws {
        let fixture = try Fixture()
        let packet = Self.packet(
            destinationCIDBytes: fixture.originalSCID.bytes,
            sourceCIDBytes: fixture.originalDCID.bytes,
            versions: [fixture.attemptedVersion, .v1]
        )

        do {
            _ = try VersionNegotiator.offeredVersions(
                inVersionNegotiationPacket: packet,
                originalDCID: fixture.originalDCID,
                originalSCID: fixture.originalSCID,
                attemptedVersion: fixture.attemptedVersion
            )
            Issue.record("Expected the attempted version to be rejected")
        } catch {
            guard case .invalidPacketFormat(let reason) = error else {
                Issue.record("Expected invalidPacketFormat, received \(error)")
                return
            }
            #expect(reason.contains("attempted version"))
        }
    }

    @Test("Connection ID construction failures map to QUICVersionError")
    func invalidConnectionIDIsMapped() throws {
        let fixture = try Fixture()
        let packet = Self.packet(
            destinationCIDBytes: [UInt8](repeating: 0x11, count: ConnectionID.maxLength + 1),
            sourceCIDBytes: fixture.originalDCID.bytes,
            versions: [.v1]
        )

        do {
            _ = try VersionNegotiator.offeredVersions(
                inVersionNegotiationPacket: packet,
                originalDCID: fixture.originalDCID,
                originalSCID: fixture.originalSCID,
                attemptedVersion: fixture.attemptedVersion
            )
            Issue.record("Expected an invalid connection ID to be rejected")
        } catch {
            guard case .invalidPacketFormat(let reason) = error else {
                Issue.record("Expected invalidPacketFormat, received \(error)")
                return
            }
            #expect(reason.contains("Invalid DCID"))
        }
    }

    private struct Fixture {
        let originalDCID: ConnectionID
        let originalSCID: ConnectionID
        let attemptedVersion = QUICVersion(rawValue: 0xFF00_001D)

        init() throws {
            originalDCID = try ConnectionID(bytes: [
                0x01, 0x02, 0x03, 0x04,
                0x05, 0x06, 0x07, 0x08,
            ])
            originalSCID = try ConnectionID(bytes: [
                0x11, 0x12, 0x13, 0x14,
                0x15, 0x16, 0x17, 0x18,
            ])
        }
    }

    private static func packet(
        destinationCIDBytes: [UInt8],
        sourceCIDBytes: [UInt8],
        versions: [QUICVersion]
    ) -> Data {
        precondition(destinationCIDBytes.count <= UInt8.max)
        precondition(sourceCIDBytes.count <= UInt8.max)

        var packet = Data([0x80, 0x00, 0x00, 0x00, 0x00])
        packet.append(UInt8(destinationCIDBytes.count))
        packet.append(contentsOf: destinationCIDBytes)
        packet.append(UInt8(sourceCIDBytes.count))
        packet.append(contentsOf: sourceCIDBytes)
        for version in versions {
            version.encode(to: &packet)
        }
        return packet
    }
}
