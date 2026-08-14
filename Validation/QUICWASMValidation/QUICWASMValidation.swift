import QUIC
import QUICWire
import QUICConnectionCore
import QUICConnectionEngineCore

private enum ValidationError: Error {
    case varintRoundTrip
    case transportParameterRoundTrip
    case connectionIdentity
    case facadeErrorContract
}

@main
struct QUICWASMValidation {
    static func main() throws {
        let value = try Varint(1_000_000)
        let encodedValue = value.encodeBytes()
        let (decodedValue, consumedLength) = try Varint.decode(from: encodedValue)
        guard decodedValue == value, consumedLength == encodedValue.count else {
            throw ValidationError.varintRoundTrip
        }

        var transportParameters = TransportParametersCore()
        transportParameters.initialMaxData = 1_048_576
        transportParameters.initialMaxStreamsBidi = 16
        let encodedParameters = try TransportParameterCodecCore.encode(transportParameters)
        let decodedParameters = try TransportParameterCodecCore.decode(encodedParameters)
        guard decodedParameters.initialMaxData == transportParameters.initialMaxData,
              decodedParameters.initialMaxStreamsBidi == transportParameters.initialMaxStreamsBidi else {
            throw ValidationError.transportParameterRoundTrip
        }

        let localConnectionID = try ConnectionID(bytes: [0, 1, 2, 3, 4, 5, 6, 7])
        let peerConnectionID = try ConnectionID(bytes: [8, 9, 10, 11, 12, 13, 14, 15])
        let configuration = QUICConnectionEngineConfiguration(
            role: .client,
            version: .v1,
            localConnectionID: localConnectionID,
            initialPeerConnectionID: peerConnectionID,
            originalDestinationConnectionID: peerConnectionID,
            localTransportParameters: transportParameters
        )
        let engine = try QUICConnectionEngine(configuration: configuration, nowNanos: 0)
        guard engine.currentDestinationConnectionID == peerConnectionID else {
            throw ValidationError.connectionIdentity
        }

        let facadeError = QUICConnectionDriverError.engine(.invalidState("validation"))
        guard case .engine(.invalidState("validation")) = facadeError else {
            throw ValidationError.facadeErrorContract
        }

        print("swift-quic WASM validation passed")
    }
}
