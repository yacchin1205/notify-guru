import CryptoKit
import UIKit
import XCTest
@testable import NotifyGuru

final class ProtocolTests: XCTestCase {
    func testSessionGridColumnsFollowDeviceAndOrientation() {
        XCTAssertEqual(SessionGridLayout.columnCount(idiom: .phone, size: CGSize(width: 390, height: 844)), 1)
        XCTAssertEqual(SessionGridLayout.columnCount(idiom: .phone, size: CGSize(width: 844, height: 390)), 1)
        XCTAssertEqual(SessionGridLayout.columnCount(idiom: .pad, size: CGSize(width: 500, height: 1_000)), 1)
        XCTAssertEqual(SessionGridLayout.columnCount(idiom: .pad, size: CGSize(width: 820, height: 1_180)), 2)
        XCTAssertEqual(SessionGridLayout.columnCount(idiom: .pad, size: CGSize(width: 1_180, height: 820)), 3)
    }

    func testPairingLinkRequiresExactV3OrV4Fragment() throws {
        let token = Base64URL.encode(Data(repeating: 1, count: 32))
        let secret = Base64URL.encode(Data(repeating: 2, count: 32))
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let publicKey = Base64URL.encode(privateKey.publicKey.x963Representation)
        let link = try PairingLink("https://notify.guru/join#v=3&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)&c=ffd6e0")
        XCTAssertEqual(link.sessionID, "session_identifier")
        XCTAssertEqual(link.protocolVersion, 3)
        XCTAssertEqual(link.color, "#ffd6e0")
        XCTAssertEqual(
            try PairingLink("https://notify.guru/join#v=4&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)&c=ffd6e0").protocolVersion,
            4
        )
        XCTAssertThrowsError(try PairingLink("https://notify.guru/join#v=2&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(publicKey)&c=ffd6e0"))
        let invalidCurvePoint = Base64URL.encode(Data(repeating: 0, count: 65))
        XCTAssertThrowsError(try PairingLink("https://notify.guru/join#v=4&s=session_identifier&p=pairing_identifier&t=\(token)&a=\(secret)&k=\(invalidCurvePoint)&c=ffd6e0"))
    }

    func testDeviceRequestLinkAuthenticatesTheRequestAndApproval() throws {
        let secret = Base64URL.encode(Data(repeating: 9, count: 32))
        let requestHash = String(repeating: "a", count: 64)
        let link = try DeviceRequestLink("https://notify.guru/device#v=3&r=request_identifier&a=\(secret)&h=\(requestHash)")
        XCTAssertEqual(link.requestID, "request_identifier")
        XCTAssertEqual(link.authSecret, secret)
        XCTAssertEqual(link.requestHash, requestHash)
        XCTAssertThrowsError(try DeviceRequestLink("https://notify.guru/device#v=3&r=request_identifier&a=\(secret)&h=\(requestHash)&g=group"))
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

    func testV4AttachmentUsesASeparateContextBoundKey() throws {
        let creator = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let groupPrivate = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 4, count: 32))
        let groupKey = GroupKey(timestamp: 42, publicKey: Base64URL.encode(groupPrivate.publicKey.x963Representation), privateKey: groupPrivate.rawRepresentation)
        let jpeg = Data([0xff, 0xd8, 0xff, 0xd9])
        let encrypted = try CryptoEngine.encryptAttachment(
            groupKey: groupKey, creatorPublicKey: Base64URL.encode(creator.publicKey.x963Representation),
            sessionID: "session", groupID: "group", responseID: "response", attachmentID: "attachment",
            jpeg: jpeg, width: 1, height: 1
        )
        let secret = try creator.sharedSecretFromKeyAgreement(with: groupPrivate.publicKey)
        let key = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(),
            sharedInfo: Data("notify.guru/attachment/v4\nsession\ngroup\n42\nresponse\nattachment".utf8), outputByteCount: 32
        )
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Base64URL.decode(encrypted.manifest.nonce)),
            ciphertext: encrypted.ciphertext.dropLast(16), tag: encrypted.ciphertext.suffix(16)
        )
        XCTAssertEqual(
            try AES.GCM.open(
                box, using: key,
                authenticating: Data("notify.guru/v4/attachment/session/group/42/response/attachment".utf8)
            ),
            jpeg
        )
        XCTAssertEqual(encrypted.manifest.ciphertextLength, Int64(jpeg.count + 16))
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
            GroupKey(timestamp: timestamp, publicKey: draft.publicKey, privateKey: draft.privateKey, transitionHash: "")
        )
    }

    func testV4TransitionChainRejectsInjectionModificationAndRollback() throws {
        var identity = try fixedIdentity()
        let member = TransitionMember(
            deviceID: identity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
        )
        let firstKey = CryptoEngine.createGroupKey()
        let firstPackage = try CryptoEngine.createKeyPackage(
            groupID: "group-identifier", key: firstKey, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let first = try CryptoEngine.createGroupTransition(
            groupID: "group-identifier", identity: identity, groupKey: firstKey,
            previous: nil, members: [member], packages: [firstPackage], recreated: true, now: 10
        )
        identity.group = DeviceGroup(
            groupID: "group-identifier",
            keys: [String(first.timestamp): GroupKey(
                timestamp: first.timestamp, publicKey: firstKey.publicKey,
                privateKey: firstKey.privateKey, transitionHash: first.transitionHash
            )],
            rootTransitionHash: first.transitionHash, headTransitionHash: first.transitionHash
        )
        let secondKey = CryptoEngine.createGroupKey()
        let secondPackage = try CryptoEngine.createKeyPackage(
            groupID: "group-identifier", key: secondKey, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let second = try CryptoEngine.createGroupTransition(
            groupID: "group-identifier", identity: identity, groupKey: secondKey,
            previous: first, members: [member], packages: [secondPackage], recreated: false, now: 11
        )
        XCTAssertEqual(
            try CryptoEngine.validateGroupTransitions(
                groupID: "group-identifier", transitions: [first, second], trustedHash: first.transitionHash
            ),
            second
        )

        let forgedContinuity = try CryptoEngine.signDevice(identity: identity, transcript: "relay forgery")
        let injectedDraft = GroupKeyRecord(
            transitionID: second.transitionID, previousHash: second.previousHash, transitionHash: "",
            timestamp: second.timestamp, actorDeviceID: second.actorDeviceID, publicKey: second.publicKey,
            recreated: second.recreated, members: second.members, packageDigests: second.packageDigests,
            actorSignature: second.actorSignature, continuitySignature: forgedContinuity
        )
        let injected = GroupKeyRecord(
            transitionID: injectedDraft.transitionID, previousHash: injectedDraft.previousHash,
            transitionHash: CryptoEngine.groupTransitionHash(
                groupID: "group-identifier", transition: injectedDraft,
                actorSignature: injectedDraft.actorSignature, continuitySignature: injectedDraft.continuitySignature
            ),
            timestamp: injectedDraft.timestamp, actorDeviceID: injectedDraft.actorDeviceID,
            publicKey: injectedDraft.publicKey, recreated: injectedDraft.recreated,
            members: injectedDraft.members, packageDigests: injectedDraft.packageDigests,
            actorSignature: injectedDraft.actorSignature, continuitySignature: injectedDraft.continuitySignature
        )
        XCTAssertThrowsError(try CryptoEngine.validateGroupTransitions(
            groupID: "group-identifier", transitions: [first, injected], trustedHash: first.transitionHash
        ))

        let changed = GroupKeyRecord(
            transitionID: second.transitionID, previousHash: second.previousHash,
            transitionHash: second.transitionHash, timestamp: second.timestamp,
            actorDeviceID: second.actorDeviceID, publicKey: second.publicKey, recreated: second.recreated,
            members: [TransitionMember(
                deviceID: member.deviceID, signingPublicKey: member.signingPublicKey,
                encryptionPublicKey: CryptoEngine.createGroupKey().publicKey
            )],
            packageDigests: second.packageDigests, actorSignature: second.actorSignature,
            continuitySignature: second.continuitySignature
        )
        XCTAssertThrowsError(try CryptoEngine.validateGroupTransitions(
            groupID: "group-identifier", transitions: [first, changed], trustedHash: first.transitionHash
        ))
        XCTAssertThrowsError(try CryptoEngine.validateGroupTransitions(
            groupID: "group-identifier", transitions: [first], trustedHash: second.transitionHash
        ))
    }

    func testV4DeviceApprovalProofBindsAcceptedTransition() throws {
        let secret = Base64URL.encode(Data(repeating: 4, count: 32))
        let proof = try CryptoEngine.deviceApprovalProof(
            authSecret: secret, requestID: "request", groupID: "group",
            transitionHash: String(repeating: "a", count: 64)
        )
        XCTAssertTrue(try CryptoEngine.verifyDeviceApprovalProof(
            authSecret: secret, requestID: "request", groupID: "group",
            transitionHash: String(repeating: "a", count: 64), proof: proof
        ))
        XCTAssertFalse(try CryptoEngine.verifyDeviceApprovalProof(
            authSecret: secret, requestID: "request", groupID: "group",
            transitionHash: String(repeating: "b", count: 64), proof: proof
        ))
    }

    func testV4SessionDescriptorAuthenticatesCreatorKey() throws {
        var identity = try fixedIdentity()
        let member = TransitionMember(
            deviceID: identity.deviceID, signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
        )
        let draft = CryptoEngine.createGroupKey()
        let package = try CryptoEngine.createKeyPackage(
            groupID: "group", key: draft, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let transition = try CryptoEngine.createGroupTransition(
            groupID: "group", identity: identity, groupKey: draft, previous: nil,
            members: [member], packages: [package], recreated: true, now: 10
        )
        let key = GroupKey(
            timestamp: transition.timestamp, publicKey: draft.publicKey, privateKey: draft.privateKey,
            transitionHash: transition.transitionHash
        )
        identity.group = DeviceGroup(groupID: "group", keys: [String(key.timestamp): key])
        let descriptor = try CryptoEngine.createSessionDescriptor(
            identity: identity, key: key, sessionID: "session", groupID: "group",
            creatorPublicKey: draft.publicKey
        )
        let invalidCurvePoint = Base64URL.encode(Data(repeating: 0, count: 65))
        XCTAssertThrowsError(try CryptoEngine.createSessionDescriptor(
            identity: identity, key: key, sessionID: "invalid-key-session", groupID: "group",
            creatorPublicKey: invalidCurvePoint
        ))
        let remote = GroupSessionResult(
            protocolVersion: 4, sessionID: descriptor.sessionID, groupID: "group",
            creatorPublicKey: descriptor.creatorPublicKey,
            expiresAt: 100, keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
            actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
            continuitySignature: descriptor.continuitySignature
        )
        XCTAssertTrue(try CryptoEngine.verifySessionDescriptor(remote, groupID: "group", transitions: [transition]))
        let invalidCreator = GroupSessionResult(
            protocolVersion: 4, sessionID: remote.sessionID, groupID: remote.groupID,
            creatorPublicKey: invalidCurvePoint, expiresAt: remote.expiresAt,
            keyTimestamp: remote.keyTimestamp, transitionHash: remote.transitionHash,
            actorDeviceID: remote.actorDeviceID, actorSignature: remote.actorSignature,
            continuitySignature: remote.continuitySignature
        )
        XCTAssertFalse(try CryptoEngine.verifySessionDescriptor(
            invalidCreator, groupID: "group", transitions: [transition]
        ))
        XCTAssertNoThrow(try CryptoEngine.authenticateInheritedSession(remote, groupID: "group", transitions: [transition]))
        let tampered = GroupSessionResult(
            protocolVersion: 4, sessionID: remote.sessionID, groupID: remote.groupID,
            creatorPublicKey: CryptoEngine.createGroupKey().publicKey, expiresAt: remote.expiresAt,
            keyTimestamp: remote.keyTimestamp, transitionHash: remote.transitionHash,
            actorDeviceID: remote.actorDeviceID, actorSignature: remote.actorSignature,
            continuitySignature: remote.continuitySignature
        )
        XCTAssertFalse(try CryptoEngine.verifySessionDescriptor(tampered, groupID: "group", transitions: [transition]))
        XCTAssertThrowsError(try CryptoEngine.authenticateInheritedSession(tampered, groupID: "group", transitions: [transition]))
        let wrongGroup = GroupSessionResult(
            protocolVersion: 4, sessionID: remote.sessionID, groupID: "other-group",
            creatorPublicKey: remote.creatorPublicKey, expiresAt: remote.expiresAt,
            keyTimestamp: remote.keyTimestamp, transitionHash: remote.transitionHash,
            actorDeviceID: remote.actorDeviceID, actorSignature: remote.actorSignature,
            continuitySignature: remote.continuitySignature
        )
        XCTAssertFalse(try CryptoEngine.verifySessionDescriptor(wrongGroup, groupID: "group", transitions: [transition]))
        XCTAssertThrowsError(try CryptoEngine.authenticateInheritedSession(wrongGroup, groupID: "group", transitions: [transition]))
        var missingGroup = try XCTUnwrap(
            JSONSerialization.jsonObject(with: JSONEncoder().encode(remote)) as? [String: Any]
        )
        missingGroup.removeValue(forKey: "groupId")
        XCTAssertThrowsError(try JSONDecoder().decode(
            GroupSessionResult.self,
            from: JSONSerialization.data(withJSONObject: missingGroup)
        ))
        let downgraded = GroupSessionResult(
            protocolVersion: 3, sessionID: remote.sessionID, groupID: remote.groupID,
            creatorPublicKey: remote.creatorPublicKey,
            expiresAt: remote.expiresAt, keyTimestamp: remote.keyTimestamp,
            transitionHash: remote.transitionHash, actorDeviceID: remote.actorDeviceID,
            actorSignature: remote.actorSignature, continuitySignature: remote.continuitySignature
        )
        XCTAssertThrowsError(try CryptoEngine.authenticateInheritedSession(downgraded, groupID: "group", transitions: [transition]))
        XCTAssertEqual(
            try CryptoEngine.authenticatedInheritedSessions(
                [downgraded, remote], groupID: "group", transitions: [transition]
            ),
            [remote]
        )
        XCTAssertEqual(
            try CryptoEngine.authenticatedInheritedSessions(
                [downgraded, tampered], groupID: "group", transitions: [transition]
            ),
            []
        )
    }

    func testV4SessionDescriptorRejectsRemovedSigner() throws {
        var removed = try fixedIdentity()
        var remaining = try CryptoEngine.createIdentity()
        remaining.deviceID = "remaining-device"
        let removedMember = TransitionMember(
            deviceID: removed.deviceID, signingPublicKey: try CryptoEngine.signingPublicKey(for: removed),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: removed)
        )
        let remainingMember = TransitionMember(
            deviceID: remaining.deviceID, signingPublicKey: try CryptoEngine.signingPublicKey(for: remaining),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: remaining)
        )
        let initialDraft = CryptoEngine.createGroupKey()
        let initialPackages = try [removedMember, remainingMember].map { member in
            try CryptoEngine.createKeyPackage(
                groupID: "group", key: initialDraft, deviceID: member.deviceID,
                encryptionPublicKey: member.encryptionPublicKey
            )
        }
        let initial = try CryptoEngine.createGroupTransition(
            groupID: "group", identity: removed, groupKey: initialDraft, previous: nil,
            members: [removedMember, remainingMember], packages: initialPackages,
            recreated: true, now: 10
        )
        let initialKey = GroupKey(
            timestamp: initial.timestamp, publicKey: initialDraft.publicKey,
            privateKey: initialDraft.privateKey, transitionHash: initial.transitionHash
        )
        removed.group = DeviceGroup(groupID: "group", keys: [String(initial.timestamp): initialKey])
        remaining.group = DeviceGroup(groupID: "group", keys: [String(initial.timestamp): initialKey])
        let removedDescriptor = try CryptoEngine.createSessionDescriptor(
            identity: removed, key: initialKey, sessionID: "removed-actor-session",
            groupID: "group", creatorPublicKey: initialDraft.publicKey
        )
        let remainingDescriptor = try CryptoEngine.createSessionDescriptor(
            identity: remaining, key: initialKey, sessionID: "remaining-actor-session",
            groupID: "group", creatorPublicKey: initialDraft.publicKey
        )
        let currentDraft = CryptoEngine.createGroupKey()
        let currentPackage = try CryptoEngine.createKeyPackage(
            groupID: "group", key: currentDraft, deviceID: remainingMember.deviceID,
            encryptionPublicKey: remainingMember.encryptionPublicKey
        )
        let current = try CryptoEngine.createGroupTransition(
            groupID: "group", identity: remaining, groupKey: currentDraft, previous: initial,
            members: [remainingMember], packages: [currentPackage], recreated: true, now: 11
        )
        XCTAssertEqual(
            try CryptoEngine.validateGroupTransitions(
                groupID: "group", transitions: [initial, current], trustedHash: initial.transitionHash
            ),
            current
        )
        func remote(_ descriptor: SignedSessionDescriptor) -> GroupSessionResult {
            GroupSessionResult(
                protocolVersion: 4, sessionID: descriptor.sessionID, groupID: descriptor.groupID,
                creatorPublicKey: descriptor.creatorPublicKey, expiresAt: 100,
                keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
                actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
                continuitySignature: descriptor.continuitySignature
            )
        }
        XCTAssertFalse(try CryptoEngine.verifySessionDescriptor(
            remote(removedDescriptor), groupID: "group", transitions: [initial, current]
        ))
        XCTAssertThrowsError(try CryptoEngine.authenticateInheritedSession(
            remote(removedDescriptor), groupID: "group", transitions: [initial, current]
        ))
        XCTAssertTrue(try CryptoEngine.verifySessionDescriptor(
            remote(remainingDescriptor), groupID: "group", transitions: [initial, current]
        ))
        XCTAssertEqual(
            try CryptoEngine.authenticatedInheritedSessions(
                [remote(removedDescriptor), remote(remainingDescriptor)],
                groupID: "group", transitions: [initial, current]
            ),
            [remote(remainingDescriptor)]
        )
    }

    func testV4TransitionRejectsRecreatedSelfRemoval() throws {
        var leaving = try fixedIdentity()
        var remaining = try CryptoEngine.createIdentity()
        remaining.deviceID = "remaining-device"
        let members = try [leaving, remaining].map { identity in
            TransitionMember(
                deviceID: identity.deviceID, signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
                encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
            )
        }
        let firstKey = CryptoEngine.createGroupKey()
        let firstPackages = try members.map { member in
            try CryptoEngine.createKeyPackage(
                groupID: "group", key: firstKey, deviceID: member.deviceID,
                encryptionPublicKey: member.encryptionPublicKey
            )
        }
        let first = try CryptoEngine.createGroupTransition(
            groupID: "group", identity: leaving, groupKey: firstKey, previous: nil,
            members: members, packages: firstPackages, recreated: true, now: 10
        )
        leaving.group = DeviceGroup(groupID: "group", keys: [String(first.timestamp): GroupKey(
            timestamp: first.timestamp, publicKey: firstKey.publicKey, privateKey: firstKey.privateKey,
            transitionHash: first.transitionHash
        )])
        let attackerKey = CryptoEngine.createGroupKey()
        let remainingPackage = try CryptoEngine.createKeyPackage(
            groupID: "group", key: attackerKey, deviceID: members[1].deviceID,
            encryptionPublicKey: members[1].encryptionPublicKey
        )
        let forged = try CryptoEngine.createGroupTransition(
            groupID: "group", identity: leaving, groupKey: attackerKey, previous: first,
            members: [members[1]], packages: [remainingPackage], recreated: true, now: 11
        )
        XCTAssertThrowsError(try CryptoEngine.validateGroupTransitions(
            groupID: "group", transitions: [first, forged], trustedHash: first.transitionHash
        ))
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
        XCTAssertEqual(GroupKeyPolicy.selectUsableKey(state)?.timestamp, 30)
        XCTAssertFalse(GroupKeyPolicy.latestKeyMatchesMembers(state))
    }

    func testGroupKeySelectionRecreatesAfterRemovalEvenWhenOlderKeyIsUsable() {
        let state = groupState(
            members: ["a"],
            keys: [
                GroupKeyRecord(timestamp: 10, publicKey: "a", recreated: true, members: ["a"]),
                GroupKeyRecord(timestamp: 20, publicKey: "ab", recreated: false, members: ["a", "b"]),
            ]
        )
        XCTAssertEqual(GroupKeyPolicy.selectUsableKey(state)?.timestamp, 20)
        XCTAssertFalse(GroupKeyPolicy.latestKeyMatchesMembers(state))
    }

    func testEventDecoderRejectsUnknownFields() throws {
        let data = Data(#"{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","createdAt":"2026-08-27T00:00:00Z","extra":true}"#.utf8)
        XCTAssertThrowsError(try EventDecoder.decode(data))
    }

    func testEventDecoderAcceptsColorAndRequestClosure() throws {
        let notification = Data(##"{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","color":"#D9F2D0","createdAt":"2026-08-27T00:00:00Z"}"##.utf8)
        guard case .notification(let id, let title, let message, let color) = try EventDecoder.decode(notification) else {
            return XCTFail("notify event decoded as another type")
        }
        XCTAssertEqual(id, "event")
        XCTAssertEqual(title, "Build")
        XCTAssertEqual(message, "Done")
        XCTAssertEqual(color, "#d9f2d0")

        let closure = Data(##"{"id":"event","type":"close_request","sessionTitle":"Build","requestId":"request","color":"#D9F2D0","createdAt":"2026-08-27T00:00:00Z"}"##.utf8)
        guard case .closeRequest(let closeTitle, let requestID, let closeColor) = try EventDecoder.decode(closure) else {
            return XCTFail("close_request event decoded as another type")
        }
        XCTAssertEqual(closeTitle, "Build")
        XCTAssertEqual(requestID, "request")
        XCTAssertEqual(closeColor, "#d9f2d0")
    }

    func testVaultRoundTripAndExpiry() throws {
        let vault = Vault(version: 4, identity: try fixedIdentity(), sessions: [session(id: "expired", expiresAt: 1_000), session(id: "current", expiresAt: 1_001)])
        XCTAssertEqual(try JSONDecoder().decode(Vault.self, from: JSONEncoder().encode(vault)), vault)
        XCTAssertEqual(AppModel.pruningExpiredSessions(from: vault, nowMilliseconds: 1_000).sessions.map(\.sessionID), ["current"])
    }

    func testRelativeTimeUsesCompactUnits() {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        XCTAssertEqual(RelativeTime.label(timestampMilliseconds: 1_999_999_998_000, now: now), "2s ago")
        XCTAssertEqual(RelativeTime.label(timestampMilliseconds: 1_999_998_800_000, now: now), "20m ago")
        XCTAssertEqual(RelativeTime.label(timestampMilliseconds: 1_999_989_200_000, now: now), "3h ago")
        XCTAssertEqual(RelativeTime.label(timestampMilliseconds: 1_999_827_200_000, now: now), "2d ago")
    }

    func testSessionRecordMigratesPreviousNotification() throws {
        let previous = Data(#"{"protocolVersion":3,"sessionID":"legacy","groupID":"group","creatorPublicKey":"creator","keys":{},"cursor":0,"title":"Session","status":"Connected","notification":"Earlier notification","expiresAt":2000}"#.utf8)
        let session = try JSONDecoder().decode(SessionRecord.self, from: previous)
        XCTAssertEqual(session.notifications, [SessionNotification(id: "legacy:legacy", message: "Earlier notification")])
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(session)) as! [String: Any]
        XCTAssertNil(encoded["notification"])
        XCTAssertNotNil(encoded["notifications"])
    }

    func testDismissResponseContainsOnlyDismissFields() throws {
        let key = Data(repeating: 9, count: 32)
        var record = session(id: "session")
        record.keys["42"] = key
        let encrypted = try CryptoEngine.encryptDismiss(
            session: record, timestamp: 42, responseID: "response", eventID: "request",
            createdAt: "2026-08-28T00:00:00Z"
        )
        let combined = try Base64URL.decode(encrypted.ciphertext)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: try Base64URL.decode(encrypted.nonce)),
            ciphertext: combined.dropLast(16), tag: combined.suffix(16)
        )
        let plaintext = try AES.GCM.open(
            box, using: SymmetricKey(data: key),
            authenticating: Data("notify.guru/v3/response/session/group/42/response".utf8)
        )
        let fields = try JSONSerialization.jsonObject(with: plaintext) as! [String: String]
        XCTAssertEqual(fields, [
            "id": "response", "type": "dismiss", "eventId": "request", "createdAt": "2026-08-28T00:00:00Z",
        ])
    }

    func testSessionCollectionCountsUnresolvedItems() {
        let notification = SessionNotification(id: "notice", message: "Notice")
        let request = SessionRequest(id: "request", prompt: "Continue?", options: [])
        var first = session(id: "one")
        first.notifications = [notification]
        first.request = request
        var second = session(id: "two")
        second.notifications = [notification]

        XCTAssertEqual([first, second].unresolvedCount, 3)
        XCTAssertEqual([SessionRecord]().unresolvedCount, 0)
    }

    func testWidgetSnapshotUsesRequestBeforeNotificationAndStatus() throws {
        var record = session(id: "widget", expiresAt: 4_000)
        record.title = "Release review"
        record.status = "Building"
        record.color = "#f2d7ee"
        record.updatedAt = 1_000
        record.notifications = [SessionNotification(id: "notice", message: "Build finished", createdAt: 2_000)]
        record.request = SessionRequest(id: "request", prompt: "Deploy this build?", options: [], createdAt: 3_000)

        let snapshot = try XCTUnwrap(WidgetSnapshotBuilder.make(from: [record]).sessions.first)
        XCTAssertEqual(snapshot.title, "Release review")
        XCTAssertEqual(snapshot.summary, "Deploy this build?")
        XCTAssertEqual(snapshot.itemKind, .request)
        XCTAssertEqual(snapshot.unresolvedCount, 2)
        XCTAssertEqual(snapshot.updatedAt, 3_000)
        XCTAssertEqual(snapshot.expiresAt, 4_000)
    }

    func testWidgetSnapshotJSONContainsOnlyPresentationFields() throws {
        var record = session(id: "widget")
        record.color = "#d6e4ff"
        let data = try JSONEncoder().encode(WidgetSnapshotBuilder.make(from: [record]))
        let root = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        XCTAssertEqual(Set(root.keys), ["sessions"])
        let sessions = root["sessions"] as! [[String: Any]]
        XCTAssertEqual(
            Set(try XCTUnwrap(sessions.first).keys),
            ["id", "title", "summary", "itemKind", "color", "unresolvedCount", "updatedAt", "expiresAt"]
        )
        XCTAssertNil(root["keys"])
        XCTAssertNil(root["accessToken"])
    }

    func testWidgetSnapshotFiltersExpiredSessions() {
        let snapshot = WidgetSnapshot(sessions: [
            WidgetSessionSnapshot(
                id: "expired", title: "Expired", summary: "Done", itemKind: .status, color: nil,
                unresolvedCount: 0, updatedAt: 500, expiresAt: 1_000
            ),
            WidgetSessionSnapshot(
                id: "active", title: "Active", summary: "Working", itemKind: .status, color: nil,
                unresolvedCount: 0, updatedAt: 500, expiresAt: 1_001
            ),
        ])
        XCTAssertEqual(snapshot.activeSessions(at: Date(timeIntervalSince1970: 1)).map(\.id), ["active"])
    }

    func testWidgetSnapshotStoreWritesOnlyWhenContentChanges() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        addTeardownBlock { try FileManager.default.removeItem(at: directory) }
        let store = WidgetSnapshotStore(directoryURL: directory)
        let snapshot = WidgetSnapshotBuilder.make(from: [session(id: "widget")])

        XCTAssertTrue(try store.saveIfChanged(snapshot))
        XCTAssertFalse(try store.saveIfChanged(snapshot))
        XCTAssertEqual(try store.load(), snapshot)
    }

    func testDetachingGroupRemovesItsV3AndV4Sessions() throws {
        var identity = try fixedIdentity()
        identity.group = DeviceGroup(groupID: "current-group", keys: [:])
        let vault = Vault(version: 4, identity: identity, sessions: [
            session(id: "current-v3", groupID: "current-group"),
            session(id: "current-v4", groupID: "current-group", protocolVersion: 4),
            session(id: "other", groupID: "other-group")
        ])
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

    private func session(
        id: String, groupID: String = "group", protocolVersion: Int = 3,
        expiresAt: Int64 = 2_000
    ) -> SessionRecord {
        SessionRecord(
            protocolVersion: protocolVersion, sessionID: id, groupID: groupID,
            creatorPublicKey: "creator-public-key",
            keys: [:], cursor: 0, title: "Session", status: "Connected", notifications: [],
            request: nil, requestKeyTimestamp: nil, color: nil, updatedAt: nil, expiresAt: expiresAt
        )
    }
}
