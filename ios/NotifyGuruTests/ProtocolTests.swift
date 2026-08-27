import CryptoKit
import XCTest
@testable import NotifyGuru

final class ProtocolTests: XCTestCase {
    func testPairingLinkRequiresExactV3Fragment() throws {
        let token = Base64URL.encode(Data(repeating: 1, count: 32))
        let secret = Base64URL.encode(Data(repeating: 2, count: 32))
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let publicKey = Base64URL.encode(privateKey.publicKey.x963Representation)
        let link = try PairingLink("https://notify.guru/join#v=3&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)")
        XCTAssertEqual(link.sessionID, "session_identifier")
        XCTAssertThrowsError(try PairingLink("https://notify.guru/join#v=2&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)"))
    }

    func testDeviceRequestLinkContainsOnlyOpaqueRequestID() throws {
        let link = try DeviceRequestLink("https://notify.guru/device#v=2&r=request_identifier")
        XCTAssertEqual(link.requestID, "request_identifier")
        XCTAssertThrowsError(try DeviceRequestLink("https://notify.guru/device#v=2&r=request_identifier&g=group"))
    }

    func testTimestampSessionKeyMatchesECDHPeer() throws {
        let creator = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let groupPrivate = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let key = GroupKey(timestamp: 1_789_999_000_001, publicKey: Base64URL.encode(groupPrivate.publicKey.x963Representation), privateKey: groupPrivate.rawRepresentation)
        let derived = try CryptoEngine.deriveSessionKey(
            key: key, creatorPublicKey: Base64URL.encode(creator.publicKey.x963Representation),
            sessionID: "session-id", groupID: "group-id"
        )
        let peerSecret = try creator.sharedSecretFromKeyAgreement(with: groupPrivate.publicKey)
        let peer = peerSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(),
            sharedInfo: Data("notify.guru/session/v3\nsession-id\ngroup-id\n1789999000001".utf8), outputByteCount: 32
        )
        XCTAssertEqual(derived, peer.withUnsafeBytes { Data($0) })
    }

    func testGroupKeyPackageRoundTrip() throws {
        let identity = try fixedIdentity()
        let draft = CryptoEngine.createGroupKey()
        let package = try CryptoEngine.createKeyPackage(
            groupID: "group-identifier", key: draft, deviceID: identity.deviceID,
            encryptionPublicKey: CryptoEngine.encryptionPublicKey(for: identity)
        )
        let timestamp: Int64 = 1_789_999_000_001
        let record = GroupKeyRecord(timestamp: timestamp, publicKey: draft.publicKey, recreated: false, members: [identity.deviceID])
        let received = KeyPackage(
            timestamp: timestamp, deviceID: package.deviceID, ephemeralPublicKey: package.ephemeralPublicKey,
            nonce: package.nonce, ciphertext: package.ciphertext
        )
        XCTAssertEqual(
            try CryptoEngine.openKeyPackage(identity: identity, groupID: "group-identifier", record: record, package: received),
            GroupKey(timestamp: timestamp, publicKey: draft.publicKey, privateKey: draft.privateKey)
        )
    }

    func testGroupKeyManagementTranscriptIsCanonical() throws {
        let packages = [
            KeyPackage(timestamp: nil, deviceID: "device_b", ephemeralPublicKey: "ephemeral-b", nonce: "nonce-b", ciphertext: "cipher-b"),
            KeyPackage(timestamp: nil, deviceID: "device_a", ephemeralPublicKey: "ephemeral-a", nonce: "nonce-a", ciphertext: "cipher-a"),
        ]
        XCTAssertEqual(
            try CryptoEngine.groupKeyRegisterTranscript(
                groupID: "group", actorDeviceID: "actor", publicKey: "group-key",
                recreated: true, members: ["device_b", "device_a"], packages: packages
            ),
            [
                "notify.guru/group-key-register/v1", "group", "actor", "group-key", "1", "2",
                "device_a", "device_b", "2",
                "device_a", "ephemeral-a", "nonce-a", "cipher-a",
                "device_b", "ephemeral-b", "nonce-b", "cipher-b",
            ].joined(separator: "\n")
        )
    }

    func testGroupKeySelectionDoesNotReviveKeyBeforeRecreatedBoundary() {
        let state = groupState(
            members: ["a", "b"],
            keys: [
                GroupKeyRecord(timestamp: 10, publicKey: "old", recreated: true, members: ["a", "b"]),
                GroupKeyRecord(timestamp: 20, publicKey: "current", recreated: true, members: ["a"]),
            ]
        )
        XCTAssertEqual(GroupKeyPolicy.selectUsableKey(state)?.timestamp, 20)
        XCTAssertFalse(GroupKeyPolicy.latestKeyMatchesMembers(state))
        XCTAssertFalse(GroupKeyPolicy.nextKeyIsRecreated(state))
    }

    func testGroupKeySelectionUsesLatestSafeKey() {
        let state = groupState(
            members: ["a", "b"],
            keys: [
                GroupKeyRecord(timestamp: 10, publicKey: "a", recreated: true, members: ["a"]),
                GroupKeyRecord(timestamp: 20, publicKey: "ab", recreated: false, members: ["a", "b"]),
                GroupKeyRecord(timestamp: 30, publicKey: "abc", recreated: false, members: ["a", "b", "c"]),
            ]
        )
        XCTAssertEqual(GroupKeyPolicy.selectUsableKey(state)?.timestamp, 20)
        XCTAssertFalse(GroupKeyPolicy.latestKeyMatchesMembers(state))
        XCTAssertTrue(GroupKeyPolicy.nextKeyIsRecreated(state))
    }

    func testGroupKeySelectionRecreatesAfterRemovalEvenWhenOlderKeyIsUsable() {
        let state = groupState(
            members: ["a"],
            keys: [
                GroupKeyRecord(timestamp: 10, publicKey: "a", recreated: true, members: ["a"]),
                GroupKeyRecord(timestamp: 20, publicKey: "ab", recreated: false, members: ["a", "b"]),
            ]
        )
        XCTAssertEqual(GroupKeyPolicy.selectUsableKey(state)?.timestamp, 10)
        XCTAssertFalse(GroupKeyPolicy.latestKeyMatchesMembers(state))
        XCTAssertTrue(GroupKeyPolicy.nextKeyIsRecreated(state))
    }

    func testEventDecoderRejectsUnknownFields() throws {
        let data = Data(#"{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","createdAt":"2026-08-27T00:00:00Z","extra":true}"#.utf8)
        XCTAssertThrowsError(try EventDecoder.decode(data))
    }

    func testVaultRoundTripAndExpiry() throws {
        let vault = Vault(version: 3, identity: try fixedIdentity(), sessions: [session(id: "expired", expiresAt: 1_000), session(id: "current", expiresAt: 1_001)])
        XCTAssertEqual(try JSONDecoder().decode(Vault.self, from: JSONEncoder().encode(vault)), vault)
        XCTAssertEqual(AppModel.pruningExpiredSessions(from: vault, nowMilliseconds: 1_000).sessions.map(\.sessionID), ["current"])
    }

    func testDetachingGroupRemovesOnlyItsV3Sessions() throws {
        var identity = try fixedIdentity()
        identity.group = DeviceGroup(groupID: "current-group", keys: [:])
        let vault = Vault(version: 3, identity: identity, sessions: [session(id: "current", groupID: "current-group"), session(id: "other", groupID: "other-group")])
        let detached = AppModel.detachingFromDeviceGroup(vault, groupID: "current-group")
        XCTAssertNil(detached.identity.group)
        XCTAssertEqual(detached.sessions.map(\.sessionID), ["other"])
    }

    func testDeviceRequestQRCodeGeneration() {
        XCTAssertNotNil(InvitationQRCode.image(for: "https://notify.guru/device#v=2&r=request"))
        XCTAssertNil(InvitationQRCode.image(for: ""))
    }

    private func fixedIdentity() throws -> DeviceIdentity {
        DeviceIdentity(
            deviceID: "device-identifier", accessToken: Base64URL.encode(Data(repeating: 8, count: 32)),
            encryptionPrivateKey: try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 6, count: 32)).rawRepresentation,
            signingPrivateKey: try P256.Signing.PrivateKey(rawRepresentation: Data(repeating: 7, count: 32)).rawRepresentation,
            group: nil
        )
    }

    private func groupState(members: [String], keys: [GroupKeyRecord]) -> DeviceGroupStateResult {
        DeviceGroupStateResult(
            groupID: "group",
            members: members.map { GroupDevice(deviceID: $0, encryptionPublicKey: "key-\($0)", addedAt: 1) },
            keys: keys,
            packages: [],
            sessions: []
        )
    }

    private func session(id: String, groupID: String = "group", expiresAt: Int64 = 2_000) -> SessionRecord {
        SessionRecord(
            protocolVersion: 3, sessionID: id, groupID: groupID, creatorPublicKey: "creator-public-key",
            keys: [:], cursor: 0, title: "Session", status: "Connected", notification: "",
            request: nil, requestKeyTimestamp: nil, expiresAt: expiresAt
        )
    }
}
