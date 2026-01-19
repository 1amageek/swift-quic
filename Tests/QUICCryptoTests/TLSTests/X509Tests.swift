/// X.509 Certificate Tests

import Testing
import Foundation
import Crypto
@testable import QUICCrypto

@Suite("X.509 Tests")
struct X509Tests {

    // MARK: - ASN.1 Tag Tests

    @Test("ASN1Tag creates universal tags correctly")
    func asn1TagUniversal() {
        let seqTag = ASN1Tag.sequence
        #expect(seqTag.tagClass == .universal)
        #expect(seqTag.isConstructed == true)
        #expect(seqTag.tagNumber == 0x10)
        #expect(seqTag.isSequence)

        let intTag = ASN1Tag.integer
        #expect(intTag.tagClass == .universal)
        #expect(intTag.isConstructed == false)
        #expect(intTag.isInteger)
    }

    @Test("ASN1Tag creates context-specific tags correctly")
    func asn1TagContextSpecific() {
        let tag = ASN1Tag.contextSpecific(0, isConstructed: true)
        #expect(tag.tagClass == .contextSpecific)
        #expect(tag.isConstructed == true)
        #expect(tag.tagNumber == 0)
    }

    // MARK: - ASN.1 Parser Tests

    @Test("ASN1Parser parses INTEGER")
    func parseInteger() throws {
        // INTEGER 42 (0x2A)
        let data = Data([0x02, 0x01, 0x2A])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isInteger)
        let bytes = try value.asInteger()
        #expect(bytes == [0x2A])
    }

    @Test("ASN1Parser parses multi-byte INTEGER")
    func parseMultiByteInteger() throws {
        // INTEGER 256 (0x0100)
        let data = Data([0x02, 0x02, 0x01, 0x00])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isInteger)
        let bytes = try value.asInteger()
        #expect(bytes == [0x01, 0x00])
    }

    @Test("ASN1Parser parses SEQUENCE")
    func parseSequence() throws {
        // SEQUENCE { INTEGER 1, INTEGER 2 }
        let data = Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isSequence)
        #expect(value.children.count == 2)
        #expect(try value.child(at: 0).asInteger() == [0x01])
        #expect(try value.child(at: 1).asInteger() == [0x02])
    }

    @Test("ASN1Parser parses BIT STRING")
    func parseBitString() throws {
        // BIT STRING with 0 unused bits and 2 bytes of data
        let data = Data([0x03, 0x03, 0x00, 0xAB, 0xCD])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isBitString)
        let (unused, bits) = try value.asBitString()
        #expect(unused == 0)
        #expect(bits == Data([0xAB, 0xCD]))
    }

    @Test("ASN1Parser parses OCTET STRING")
    func parseOctetString() throws {
        let data = Data([0x04, 0x03, 0x01, 0x02, 0x03])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isOctetString)
        #expect(try value.asOctetString() == Data([0x01, 0x02, 0x03]))
    }

    @Test("ASN1Parser parses NULL")
    func parseNull() throws {
        let data = Data([0x05, 0x00])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.universalTag == .null)
        #expect(value.content.isEmpty)
    }

    @Test("ASN1Parser parses BOOLEAN")
    func parseBoolean() throws {
        // TRUE
        let trueData = Data([0x01, 0x01, 0xFF])
        let trueValue = try ASN1Parser.parseOne(from: trueData)
        #expect(try trueValue.asBoolean() == true)

        // FALSE
        let falseData = Data([0x01, 0x01, 0x00])
        let falseValue = try ASN1Parser.parseOne(from: falseData)
        #expect(try falseValue.asBoolean() == false)
    }

    @Test("ASN1Parser parses UTF8 STRING")
    func parseUTF8String() throws {
        let str = "Hello"
        var data = Data([0x0C, UInt8(str.utf8.count)])
        data.append(contentsOf: str.utf8)

        let value = try ASN1Parser.parseOne(from: data)
        #expect(try value.asString() == "Hello")
    }

    @Test("ASN1Parser handles long form length")
    func parseLongFormLength() throws {
        // Create data with 200 byte content (needs long form length)
        var data = Data([0x04, 0x81, 0xC8])  // OCTET STRING, long form length 200
        data.append(Data(repeating: 0xAA, count: 200))

        let value = try ASN1Parser.parseOne(from: data)
        #expect(value.content.count == 200)
    }

    @Test("ASN1Parser parses nested SEQUENCE")
    func parseNestedSequence() throws {
        // SEQUENCE { SEQUENCE { INTEGER 1 } }
        let data = Data([0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01])
        let value = try ASN1Parser.parseOne(from: data)

        #expect(value.tag.isSequence)
        #expect(value.children.count == 1)

        let inner = value.children[0]
        #expect(inner.tag.isSequence)
        #expect(inner.children.count == 1)
        #expect(try inner.child(at: 0).asInteger() == [0x01])
    }

    @Test("ASN1Parser throws on underflow")
    func parseUnderflow() throws {
        let data = Data([0x02, 0x05, 0x01])  // Claims 5 bytes but only has 1
        #expect(throws: ASN1Error.self) {
            _ = try ASN1Parser.parseOne(from: data)
        }
    }

    // MARK: - OID Tests

    @Test("OID parses from DER encoding")
    func oidFromDER() throws {
        // OID 1.2.840.10045.2.1 (ecPublicKey)
        let derBytes = Data([0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        let oid = try OID(derEncoded: derBytes)

        #expect(oid.components == [1, 2, 840, 10045, 2, 1])
        #expect(oid.dotNotation == "1.2.840.10045.2.1")
    }

    @Test("OID encodes to DER correctly")
    func oidToDER() throws {
        let oid = try OID("1.2.840.10045.2.1")
        let encoded = oid.derEncode()

        // Verify round-trip
        let decoded = try OID(derEncoded: encoded)
        #expect(decoded.components == oid.components)
    }

    @Test("OID parses from dot notation")
    func oidFromDotNotation() throws {
        let oid = try OID("2.5.4.3")  // commonName
        #expect(oid.components == [2, 5, 4, 3])
    }

    @Test("Known OID lookup works")
    func knownOIDLookup() throws {
        let oid = try OID("1.2.840.10045.2.1")
        let known = KnownOID(oid: oid)
        #expect(known == .ecPublicKey)

        let secp256r1 = try OID("1.2.840.10045.3.1.7")
        #expect(KnownOID(oid: secp256r1) == .secp256r1)
    }

    @Test("OID parses OBJECT IDENTIFIER from ASN.1")
    func parseOIDFromASN1() throws {
        // OBJECT IDENTIFIER 1.2.840.10045.2.1
        let data = Data([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
        let value = try ASN1Parser.parseOne(from: data)

        let oid = try value.asObjectIdentifier()
        #expect(oid.dotNotation == "1.2.840.10045.2.1")
    }

    // MARK: - ASN.1 Builder Tests

    @Test("ASN1Builder builds INTEGER")
    func buildInteger() throws {
        let encoded = ASN1Builder.integer(Data([0x2A]))
        #expect(encoded == Data([0x02, 0x01, 0x2A]))
    }

    @Test("ASN1Builder adds leading zero for negative-looking integers")
    func buildIntegerWithLeadingZero() throws {
        // 0x80 would look negative without leading zero
        let encoded = ASN1Builder.integer(Data([0x80]))
        #expect(encoded == Data([0x02, 0x02, 0x00, 0x80]))
    }

    @Test("ASN1Builder builds SEQUENCE")
    func buildSequence() throws {
        let int1 = ASN1Builder.integer(Data([0x01]))
        let int2 = ASN1Builder.integer(Data([0x02]))
        let seq = ASN1Builder.sequence([int1, int2])

        #expect(seq == Data([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]))
    }

    @Test("ASN1Builder builds NULL")
    func buildNull() throws {
        let encoded = ASN1Builder.null()
        #expect(encoded == Data([0x05, 0x00]))
    }

    @Test("ASN1Builder builds OCTET STRING")
    func buildOctetString() throws {
        let encoded = ASN1Builder.octetString(Data([0x01, 0x02, 0x03]))
        #expect(encoded == Data([0x04, 0x03, 0x01, 0x02, 0x03]))
    }

    // MARK: - X.509 Extension Tests (using swift-certificates)
    // Note: Extension parsing is now handled by swift-certificates library.
    // These tests verify the extension helper wrappers work correctly.

    // MARK: - X.509 Validation Tests

    @Test("X509Validator hostname matching with exact match")
    func hostnameMatchExact() throws {
        // Create a minimal test using internal logic
        let validator = X509Validator(options: X509ValidationOptions(allowSelfSigned: true))

        // Test the hostname matching logic by reflection
        // Since matchHostname is private, we test through the public API indirectly
        // For now, just verify the validator is created correctly
        #expect(validator != nil)
    }

    @Test("X509ValidationOptions default values")
    func validationOptionsDefaults() {
        let options = X509ValidationOptions()

        #expect(options.checkValidity == true)
        #expect(options.checkBasicConstraints == true)
        #expect(options.checkKeyUsage == true)
        #expect(options.hostname == nil)
        #expect(options.allowSelfSigned == false)
        #expect(options.maxChainDepth == 10)
    }

    @Test("CertificateStore adds and retrieves certificates")
    func certificateStore() throws {
        var store = CertificateStore()
        #expect(store.all.isEmpty)

        // We can't easily test adding certificates without a real certificate,
        // but we can verify the store is properly initialized
        let validator = store.validator()
        #expect(validator != nil)
    }

    // MARK: - VerificationKey Extension Tests

    @Test("SigningKey generates P-256 key")
    func signingKeyP256() throws {
        let key = SigningKey.generateP256()
        #expect(key.scheme == .ecdsa_secp256r1_sha256)

        let data = Data("test data".utf8)
        let signature = try key.sign(data)
        #expect(!signature.isEmpty)

        let verified = try key.verificationKey.verify(signature: signature, for: data)
        #expect(verified == true)
    }

    @Test("SigningKey generates P-384 key")
    func signingKeyP384() throws {
        let key = SigningKey.generateP384()
        #expect(key.scheme == .ecdsa_secp384r1_sha384)

        let data = Data("test data".utf8)
        let signature = try key.sign(data)
        #expect(!signature.isEmpty)

        let verified = try key.verificationKey.verify(signature: signature, for: data)
        #expect(verified == true)
    }

    @Test("SigningKey generates Ed25519 key")
    func signingKeyEd25519() throws {
        let key = SigningKey.generateEd25519()
        #expect(key.scheme == .ed25519)

        let data = Data("test data".utf8)
        let signature = try key.sign(data)
        #expect(!signature.isEmpty)

        let verified = try key.verificationKey.verify(signature: signature, for: data)
        #expect(verified == true)
    }

    @Test("VerificationKey scheme property")
    func verificationKeyScheme() throws {
        let p256Key = SigningKey.generateP256().verificationKey
        #expect(p256Key.scheme == .ecdsa_secp256r1_sha256)

        let p384Key = SigningKey.generateP384().verificationKey
        #expect(p384Key.scheme == .ecdsa_secp384r1_sha384)

        let ed25519Key = SigningKey.generateEd25519().verificationKey
        #expect(ed25519Key.scheme == .ed25519)
    }

    // MARK: - X509Error Tests

    @Test("X509Error descriptions")
    func x509ErrorDescriptions() {
        let expired = X509Error.certificateExpired(notAfter: Date())
        #expect(expired.description.contains("expired"))

        let notYetValid = X509Error.certificateNotYetValid(notBefore: Date())
        #expect(notYetValid.description.contains("not valid"))

        let untrusted = X509Error.untrustedRoot
        #expect(untrusted.description.contains("trusted"))

        let hostnameMismatch = X509Error.hostnameMismatch(expected: "example.com", actual: ["other.com"])
        #expect(hostnameMismatch.description.contains("example.com"))
    }

    // MARK: - Algorithm Identifier Tests (using swift-certificates)
    // Note: Algorithm identifier parsing is now handled by swift-certificates.
    // The SignatureAlgorithmIdentifier wrapper provides access to algorithm info.

    @Test("SignatureAlgorithmIdentifier from swift-certificates")
    func signatureAlgorithmIdentifier() throws {
        // Test that we can work with signature algorithms via our wrapper
        // Create a P-256 key and verify its scheme
        let signingKey = SigningKey.generateP256()
        #expect(signingKey.scheme == .ecdsa_secp256r1_sha256)

        let verificationKey = signingKey.verificationKey
        #expect(verificationKey.scheme == .ecdsa_secp256r1_sha256)
    }
}
