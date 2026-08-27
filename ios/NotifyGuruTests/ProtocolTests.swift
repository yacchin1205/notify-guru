import CryptoKit
import XCTest
@testable import NotifyGuru

final class ProtocolTests: XCTestCase {
    func testPairingLinkRequiresExactV2Fragment() throws {
        let token = Base64URL.encode(Data(repeating: 1, count: 32))
        let secret = Base64URL.encode(Data(repeating: 2, count: 32))
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let publicKey = Base64URL.encode(privateKey.publicKey.x963Representation)
        let link = try PairingLink("https://notify.guru/join#v=2&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)")

        XCTAssertEqual(link.sessionID, "session_identifier")
        XCTAssertThrowsError(try PairingLink("https://notify.guru/join#v=2&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)&extra=true"))
    }

    func testGenerationSessionKeyMatchesECDHPeer() throws {
        let creator = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let groupPrivate = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let generation = GenerationKey(
            generation: 7,
            publicKey: Base64URL.encode(groupPrivate.publicKey.x963Representation),
            privateKey: groupPrivate.rawRepresentation
        )
        let derived = try CryptoEngine.deriveSessionKey(
            generation: generation,
            creatorPublicKey: Base64URL.encode(creator.publicKey.x963Representation),
            sessionID: "session-id",
            groupID: "group-id"
        )
        let peerSecret = try creator.sharedSecretFromKeyAgreement(with: groupPrivate.publicKey)
        let peer = peerSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data("notify.guru/session/v2\nsession-id\ngroup-id\n7".utf8),
            outputByteCount: 32
        )
        XCTAssertEqual(derived, peer.withUnsafeBytes { Data($0) })
        XCTAssertEqual(Base64URL.encode(derived), "gXfVAK1yzHMsFX5qQc5sXTEFOXSfDSEVcmNWknyoHgQ")
    }

    func testGenerationPackageRoundTripAndSignatures() throws {
        let identity = try fixedIdentity()
        let generation = CryptoEngine.createGeneration(1)
        let package = try CryptoEngine.createKeyPackage(
            groupID: "group-identifier",
            generation: generation,
            deviceID: identity.deviceID,
            encryptionPublicKey: CryptoEngine.encryptionPublicKey(for: identity)
        )
        XCTAssertEqual(
            try CryptoEngine.openKeyPackage(
                identity: identity,
                groupID: "group-identifier",
                expectedPublicKey: generation.publicKey,
                package: package
            ),
            generation
        )
        let hash = CryptoEngine.hashPackages([package])
        let transcript = try CryptoEngine.groupCreateTranscript(
            groupID: "group-identifier", identity: identity, generation: generation, packagesHash: hash
        )
        let signature = try CryptoEngine.signDevice(identity: identity, transcript: transcript)
        XCTAssertTrue(try CryptoEngine.verify(
            publicKey: CryptoEngine.signingPublicKey(for: identity), signature: signature, transcript: transcript
        ))
    }

    func testDecryptsLegacyGoEventVector() throws {
        let session = legacySession(id: "session-id", expiresAt: 1)
        let envelope = EventEnvelope(
            sequence: 1,
            eventID: "event-id",
            groupID: "first",
            generation: nil,
            nonce: "BQUFBQUFBQUFBQUF",
            ciphertext: "OzZ_nSEMbRHBMJSlsDuAdnPzTFnot1-_kPLLyMolGCimmFQOP7y_PuDnxwK9X8DJj7pXPloDhoOVERbJEDqzoHkfmTMz6bX-_iXgBlJunarXseLIdfEUXc-DxfapQgI_Io4_SYhuu7RqGovKQ8uPpFn6XtONGgxPCQ",
            createdAt: 0
        )
        guard case .notification(let title, let message) = try CryptoEngine.decryptEvent(session: session, envelope: envelope) else {
            return XCTFail("Go event vector did not decode as notify")
        }
        XCTAssertEqual(title, "Build")
        XCTAssertEqual(message, "Done")
    }

    func testEventDecoderRejectsUnknownFields() throws {
        let data = Data(#"{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","createdAt":"2026-08-27T00:00:00Z","extra":true}"#.utf8)
        XCTAssertThrowsError(try EventDecoder.decode(data))
    }

    func testVaultRoundTrip() throws {
        let vault = Vault(version: 2, identity: try fixedIdentity(), sessions: [])
        XCTAssertEqual(try JSONDecoder().decode(Vault.self, from: JSONEncoder().encode(vault)), vault)
    }

    func testPrunesExpiredSessionsWithoutServerAccess() throws {
        let vault = Vault(
            version: 2,
            identity: try fixedIdentity(),
            sessions: [legacySession(id: "expired", expiresAt: 1_000), legacySession(id: "current", expiresAt: 1_001)]
        )
        let pruned = AppModel.pruningExpiredSessions(from: vault, nowMilliseconds: 1_000)
        XCTAssertEqual(pruned.sessions.map(\.sessionID), ["current"])
    }

    private func fixedIdentity() throws -> DeviceIdentity {
        DeviceIdentity(
            deviceID: "device-identifier",
            accessToken: Base64URL.encode(Data(repeating: 8, count: 32)),
            encryptionPrivateKey: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 6, count: 32)).rawRepresentation,
            signingPrivateKey: try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32)).rawRepresentation,
            group: nil,
            pendingInvitation: nil,
            invitations: [:]
        )
    }

    private func legacySession(id: String, expiresAt: Int64) -> SessionRecord {
        SessionRecord(
            protocolVersion: 1,
            sessionID: id,
            groupID: "first",
            groupAccessToken: "sensitive-token",
            sharedKey: try! Base64URL.decode("uaEVrcIWs4cNzciEiU3iqSyYpjF_bNrUm3lu4YXRUZA"),
            creatorPublicKey: nil,
            generationKeys: [:],
            cursor: 0,
            title: "Decrypted title",
            status: "Decrypted status",
            notification: "Decrypted notification",
            request: nil,
            requestGeneration: nil,
            expiresAt: expiresAt
        )
    }
}
