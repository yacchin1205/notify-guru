import CryptoKit
import Foundation
import Security

enum CryptoEngine {
    static func createIdentity() throws -> DeviceIdentity {
        DeviceIdentity(
            deviceID: "",
            accessToken: try randomToken(),
            encryptionPrivateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            signingPrivateKey: P256.Signing.PrivateKey().rawRepresentation,
            group: nil
        )
    }

    static func encryptionPublicKey(for identity: DeviceIdentity) throws -> String {
        Base64URL.encode(try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.encryptionPrivateKey).publicKey.x963Representation)
    }

    static func signingPublicKey(for identity: DeviceIdentity) throws -> String {
        Base64URL.encode(try P256.Signing.PrivateKey(rawRepresentation: identity.signingPrivateKey).publicKey.x963Representation)
    }

    static func createGroupKey(timestamp: Int64 = 0) -> GroupKey {
        let key = P256.KeyAgreement.PrivateKey()
        return GroupKey(timestamp: timestamp, publicKey: Base64URL.encode(key.publicKey.x963Representation), privateKey: key.rawRepresentation)
    }

    static func createKeyPackage(groupID: String, key: GroupKey, deviceID: String, encryptionPublicKey: String) throws -> KeyPackage {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(encryptionPublicKey))
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let context = packageContext(groupID: groupID, publicKey: key.publicKey, deviceID: deviceID)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(context.utf8), outputByteCount: 32
        )
        let plaintext = Data(["notify.guru/group-key/v2", key.publicKey, Base64URL.encode(key.privateKey)].joined(separator: "\n").utf8)
        let nonceData = try randomData(count: 12)
        let sealed = try AES.GCM.seal(
            plaintext, using: wrappingKey, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: Data(context.utf8)
        )
        return KeyPackage(
            timestamp: nil, deviceID: deviceID,
            ephemeralPublicKey: Base64URL.encode(ephemeral.publicKey.x963Representation),
            nonce: Base64URL.encode(nonceData), ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag)
        )
    }

    static func openKeyPackage(identity: DeviceIdentity, groupID: String, record: GroupKeyRecord, package: KeyPackage) throws -> GroupKey {
        guard package.deviceID == identity.deviceID, package.timestamp == record.timestamp else {
            throw ProtocolError.crypto("key package target or timestamp does not match")
        }
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.encryptionPrivateKey)
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(package.ephemeralPublicKey))
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let context = packageContext(groupID: groupID, publicKey: record.publicKey, deviceID: identity.deviceID)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data(context.utf8), outputByteCount: 32
        )
        let combined = try Base64URL.decode(package.ciphertext)
        guard combined.count >= 16 else { throw ProtocolError.crypto("key package is shorter than its tag") }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: try Base64URL.decode(package.nonce)),
            ciphertext: combined.dropLast(16), tag: combined.suffix(16)
        )
        let plaintext = try AES.GCM.open(box, using: wrappingKey, authenticating: Data(context.utf8))
        guard let decoded = String(data: plaintext, encoding: .utf8) else { throw ProtocolError.crypto("key package plaintext is not UTF-8") }
        let fields = decoded.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 3, fields[0] == "notify.guru/group-key/v2", fields[1] == record.publicKey else {
            throw ProtocolError.crypto("key package plaintext has invalid fields")
        }
        let key = GroupKey(
            timestamp: record.timestamp, publicKey: fields[1], privateKey: try Base64URL.decode(fields[2]),
            transitionHash: record.transitionHash
        )
        let parsed = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.privateKey)
        guard Base64URL.encode(parsed.publicKey.x963Representation) == key.publicKey else {
            throw ProtocolError.crypto("group private and public keys do not match")
        }
        return key
    }

    static func deriveSessionKey(key: GroupKey, creatorPublicKey: String, sessionID: String, groupID: String, protocolVersion: Int = 3) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.privateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(creatorPublicKey))
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let info = Data("notify.guru/session/v\(protocolVersion)\n\(sessionID)\n\(groupID)\n\(key.timestamp)".utf8)
        return symmetricData(secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32))
    }

    static func pairingProof(authSecret: String, protocolVersion: Int, sessionID: String, pairingID: String, groupID: String, timestamp: Int64, groupPublicKey: String, transitionHash: String?) throws -> String {
        var fields = ["v\(protocolVersion)", sessionID, pairingID, groupID, String(timestamp), groupPublicKey]
        if protocolVersion == 4 {
            guard let transitionHash else { throw ProtocolError.crypto("version 4 pairing has no transition hash") }
            fields.append(transitionHash)
        }
        let transcript = fields.joined(separator: "\n")
        let authentication = HMAC<SHA256>.authenticationCode(
            for: Data(transcript.utf8), using: SymmetricKey(data: try Base64URL.decode(authSecret))
        )
        return Base64URL.encode(Data(authentication))
    }

    static func sessionDescriptorTranscript(
        sessionID: String, groupID: String, protocolVersion: Int, creatorPublicKey: String,
        keyTimestamp: Int64, transitionHash: String, actorDeviceID: String
    ) -> String {
        [
            "notify.guru/session-descriptor/v1", sessionID, groupID, String(protocolVersion), creatorPublicKey,
            String(keyTimestamp), transitionHash, actorDeviceID,
        ].joined(separator: "\n")
    }

    static func createSessionDescriptor(
        identity: DeviceIdentity, key: GroupKey, sessionID: String, groupID: String, creatorPublicKey: String
    ) throws -> SignedSessionDescriptor {
        guard let transitionHash = key.transitionHash else { throw ProtocolError.crypto("group key has no transition hash") }
        _ = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(creatorPublicKey))
        let transcript = sessionDescriptorTranscript(
            sessionID: sessionID, groupID: groupID, protocolVersion: 4, creatorPublicKey: creatorPublicKey,
            keyTimestamp: key.timestamp, transitionHash: transitionHash, actorDeviceID: identity.deviceID
        )
        let continuityKey = try P256.Signing.PrivateKey(rawRepresentation: key.privateKey)
        return SignedSessionDescriptor(
            sessionID: sessionID, groupID: groupID, protocolVersion: 4, creatorPublicKey: creatorPublicKey,
            keyTimestamp: key.timestamp, transitionHash: transitionHash, actorDeviceID: identity.deviceID,
            actorSignature: try signDevice(identity: identity, transcript: transcript),
            continuitySignature: Base64URL.encode(try continuityKey.signature(for: Data(transcript.utf8)).rawRepresentation)
        )
    }

    static func verifySessionDescriptor(
        _ remote: GroupSessionResult, groupID: String, transitions: [GroupKeyRecord]
    ) throws -> Bool {
        guard (try? P256.KeyAgreement.PublicKey(
            x963Representation: Base64URL.decode(remote.creatorPublicKey)
        )) != nil else { return false }
        guard remote.protocolVersion == 4, remote.groupID == groupID, let keyTimestamp = remote.keyTimestamp,
              let transitionHash = remote.transitionHash, let actorDeviceID = remote.actorDeviceID,
              let actorSignature = remote.actorSignature, let continuitySignature = remote.continuitySignature,
              let transition = transitions.first(where: {
                  $0.timestamp == keyTimestamp && $0.transitionHash == transitionHash
              }), let actor = transition.members.first(where: { $0.deviceID == actorDeviceID }),
              let currentActor = transitions.last?.members.first(where: { $0.deviceID == actorDeviceID }),
              currentActor.signingPublicKey == actor.signingPublicKey,
              currentActor.encryptionPublicKey == actor.encryptionPublicKey else { return false }
        let transcript = sessionDescriptorTranscript(
            sessionID: remote.sessionID, groupID: groupID, protocolVersion: 4,
            creatorPublicKey: remote.creatorPublicKey, keyTimestamp: keyTimestamp,
            transitionHash: transitionHash, actorDeviceID: actorDeviceID
        )
        return try verifySignature(publicKey: actor.signingPublicKey, signature: actorSignature, transcript: transcript)
            && verifySignature(publicKey: transition.publicKey, signature: continuitySignature, transcript: transcript)
    }

    static func authenticateInheritedSession(
        _ remote: GroupSessionResult, groupID: String, transitions: [GroupKeyRecord]
    ) throws {
        guard remote.protocolVersion == 4 else {
            throw ProtocolError.crypto("relay supplied an unauthenticated session descriptor")
        }
        guard try verifySessionDescriptor(remote, groupID: groupID, transitions: transitions) else {
            throw ProtocolError.crypto("relay supplied an unauthenticated session descriptor")
        }
    }

    static func authenticatedInheritedSessions(
        _ sessions: [GroupSessionResult], groupID: String, transitions: [GroupKeyRecord]
    ) throws -> [GroupSessionResult] {
        sessions.compactMap { remote in
            guard remote.protocolVersion == 4 else { return nil }
            return (try? verifySessionDescriptor(remote, groupID: groupID, transitions: transitions)) == true
                ? remote : nil
        }
    }

    static func deviceCreateTranscript(signingPublicKey: String, nonce: String) -> String {
        ["notify.guru/device-create/v1", signingPublicKey, nonce].joined(separator: "\n")
    }

    static func groupCreateTranscript(groupID: String, identity: DeviceIdentity, accessHash: String) throws -> String {
        ["notify.guru/group-create/v2", groupID, identity.deviceID, accessHash, try encryptionPublicKey(for: identity)].joined(separator: "\n")
    }

    static func deviceRequestTranscript(requestID: String, identity: DeviceIdentity, accessHash: String, protocolVersion: Int = 3) throws -> String {
        let fields = [
            protocolVersion == 4 ? "notify.guru/device-request/v2" : "notify.guru/device-request/v1",
            requestID, identity.deviceID, accessHash, try encryptionPublicKey(for: identity),
        ] + (protocolVersion == 4 ? ["3,4"] : [])
        return fields.joined(separator: "\n")
    }

    static func deviceRequestReadTranscript(requestID: String, deviceID: String) -> String {
        ["notify.guru/device-request-read/v1", requestID, deviceID].joined(separator: "\n")
    }

    static func groupKeyRegisterTranscript(
        groupID: String,
        actorDeviceID: String,
        publicKey: String,
        recreated: Bool,
        members: [String],
        packages: [KeyPackage]
    ) throws -> String {
        let sortedMembers = members.sorted { $0.utf8.lexicographicallyPrecedes($1.utf8) }
        let packagesByDevice = Dictionary(uniqueKeysWithValues: packages.map { ($0.deviceID, $0) })
        var lines = [
            "notify.guru/group-key-register/v1",
            groupID,
            actorDeviceID,
            publicKey,
            recreated ? "1" : "0",
            String(sortedMembers.count),
        ]
        lines.append(contentsOf: sortedMembers)
        lines.append(String(packages.count))
        for deviceID in sortedMembers {
            guard let package = packagesByDevice[deviceID] else {
                throw ProtocolError.crypto("group key package set is incomplete")
            }
            lines.append(contentsOf: [
                package.deviceID, package.ephemeralPublicKey, package.nonce, package.ciphertext,
            ])
        }
        return lines.joined(separator: "\n")
    }

    static func groupDeviceApproveTranscript(groupID: String, actorDeviceID: String, requestID: String) -> String {
        ["notify.guru/group-device-approve/v1", groupID, actorDeviceID, requestID].joined(separator: "\n")
    }

    static func groupDeviceRemoveTranscript(groupID: String, actorDeviceID: String, deviceID: String) -> String {
        ["notify.guru/group-device-remove/v1", groupID, actorDeviceID, deviceID].joined(separator: "\n")
    }

    static func groupAbandonTranscript(groupID: String, actorDeviceID: String, headTransitionHash: String) -> String {
        ["notify.guru/group-abandon/v1", groupID, actorDeviceID, headTransitionHash].joined(separator: "\n")
    }

    static func createGroupTransition(
        groupID: String,
        identity: DeviceIdentity,
        groupKey: GroupKey,
        previous: GroupKeyRecord?,
        members: [TransitionMember],
        packages: [KeyPackage],
        recreated: Bool,
        now: Int64 = Int64(Date().timeIntervalSince1970 * 1_000)
    ) throws -> GroupKeyRecord {
        let digests = try packages.map {
            TransitionPackageDigest(deviceID: $0.deviceID, sha256: try groupKeyPackageDigest($0))
        }
        let unsigned = GroupKeyRecord(
            transitionID: try randomID(), previousHash: previous?.transitionHash ?? String(repeating: "0", count: 64),
            transitionHash: "", timestamp: max(now, (previous?.timestamp ?? 0) + 1),
            actorDeviceID: identity.deviceID, publicKey: groupKey.publicKey, recreated: recreated,
            members: members, packageDigests: digests, actorSignature: "", continuitySignature: ""
        )
        let transcript = groupTransitionTranscript(groupID: groupID, transition: unsigned)
        let actorSignature = try signDevice(identity: identity, transcript: transcript)
        let continuityKey: GroupKey
        if let previous {
            guard let value = identity.group?.keys[String(previous.timestamp)], value.publicKey == previous.publicKey else {
                throw ProtocolError.crypto("previous group private key is unavailable")
            }
            continuityKey = value
        } else {
            continuityKey = groupKey
        }
        let signingKey = try P256.Signing.PrivateKey(rawRepresentation: continuityKey.privateKey)
        let continuitySignature = Base64URL.encode(try signingKey.signature(for: Data(transcript.utf8)).rawRepresentation)
        let hash = groupTransitionHash(
            groupID: groupID, transition: unsigned,
            actorSignature: actorSignature, continuitySignature: continuitySignature
        )
        return GroupKeyRecord(
            transitionID: unsigned.transitionID, previousHash: unsigned.previousHash, transitionHash: hash,
            timestamp: unsigned.timestamp, actorDeviceID: unsigned.actorDeviceID, publicKey: unsigned.publicKey,
            recreated: unsigned.recreated, members: members, packageDigests: digests,
            actorSignature: actorSignature, continuitySignature: continuitySignature
        )
    }

    static func groupTransitionTranscript(groupID: String, transition: GroupKeyRecord) -> String {
        let members = transition.members.sorted { canonicalLess($0.deviceID, $1.deviceID) }
        let digests = transition.packageDigests.sorted { canonicalLess($0.deviceID, $1.deviceID) }
        var lines = [
            "notify.guru/group-transition/v1", groupID, transition.transitionID, transition.previousHash,
            String(transition.timestamp), transition.actorDeviceID, transition.publicKey,
            transition.recreated ? "1" : "0", String(members.count),
        ]
        for member in members {
            lines.append(contentsOf: [member.deviceID, member.signingPublicKey, member.encryptionPublicKey])
        }
        lines.append(String(digests.count))
        for digest in digests { lines.append(contentsOf: [digest.deviceID, digest.sha256]) }
        return lines.joined(separator: "\n")
    }

    static func groupTransitionHash(
        groupID: String, transition: GroupKeyRecord, actorSignature: String, continuitySignature: String
    ) -> String {
        hashText([
            "notify.guru/group-transition-hash/v2", groupTransitionTranscript(groupID: groupID, transition: transition),
        ].joined(separator: "\n"))
    }

    static func validateGroupTransitions(
        groupID: String, transitions: [GroupKeyRecord], trustedHash: String
    ) throws -> GroupKeyRecord {
        guard !transitions.isEmpty else { throw ProtocolError.crypto("group transition chain is empty") }
        var previous: GroupKeyRecord?
        var trustedSeen = false
        for transition in transitions {
            guard transition.previousHash == (previous?.transitionHash ?? String(repeating: "0", count: 64)) else {
                throw ProtocolError.crypto("group transition chain is not contiguous")
            }
            if let previous, transition.timestamp <= previous.timestamp {
                throw ProtocolError.crypto("group transition timestamp did not advance")
            }
            let expectedHash = groupTransitionHash(
                groupID: groupID, transition: transition,
                actorSignature: transition.actorSignature, continuitySignature: transition.continuitySignature
            )
            guard expectedHash == transition.transitionHash else {
                throw ProtocolError.crypto("group transition hash is invalid")
            }
            let authorizedMembers = previous?.members ?? transition.members
            guard let actor = authorizedMembers.first(where: { $0.deviceID == transition.actorDeviceID }) else {
                throw ProtocolError.crypto("group transition actor is not authorized")
            }
            let transcript = groupTransitionTranscript(groupID: groupID, transition: transition)
            guard try verifySignature(publicKey: actor.signingPublicKey, signature: transition.actorSignature, transcript: transcript) else {
                throw ProtocolError.crypto("group transition actor signature is invalid")
            }
            guard try verifySignature(
                publicKey: previous?.publicKey ?? transition.publicKey,
                signature: transition.continuitySignature,
                transcript: transcript
            ) else { throw ProtocolError.crypto("group transition continuity signature is invalid") }
            let memberIDs = transition.members.map(\.deviceID)
            let packageIDs = transition.packageDigests.map(\.deviceID)
            guard Set(memberIDs).count == memberIDs.count,
                  Set(packageIDs).count == packageIDs.count,
                  Set(memberIDs) == Set(packageIDs) else {
                throw ProtocolError.crypto("group transition package set is invalid")
            }
            if previous == nil, !transition.recreated {
                throw ProtocolError.crypto("genesis transition must create a fresh key")
            }
            if let previous {
                let nextMembers = Set(memberIDs)
                let removed = previous.members.filter { !nextMembers.contains($0.deviceID) }
                let previousByID = Dictionary(uniqueKeysWithValues: previous.members.map { ($0.deviceID, $0) })
                for member in transition.members {
                    if let before = previousByID[member.deviceID], before != member {
                        throw ProtocolError.crypto("retained group member descriptor changed")
                    }
                }
                let actorRemoved = removed.contains { $0.deviceID == transition.actorDeviceID }
                if actorRemoved,
                   (removed.count != 1 || transition.recreated || transition.publicKey != previous.publicKey
                    || transition.members.contains { previousByID[$0.deviceID] == nil }) {
                    throw ProtocolError.crypto("self-removal must be a same-key marker removing only its actor")
                }
                if !removed.isEmpty, !actorRemoved,
                   (!transition.recreated || transition.publicKey == previous.publicKey) {
                    throw ProtocolError.crypto("removing another device must create a fresh group key")
                }
                if let previousIndex = transitions.firstIndex(where: { $0.transitionHash == previous.previousHash }),
                   !previous.recreated {
                    let beforePrevious = transitions[previousIndex]
                    let previousIDs = Set(previous.members.map(\.deviceID))
                    let previousWasMarker = beforePrevious.members.contains { !previousIDs.contains($0.deviceID) }
                    if previousWasMarker,
                       (!transition.recreated || transition.publicKey == previous.publicKey
                        || Set(memberIDs) != previousIDs) {
                        throw ProtocolError.crypto("removal marker must be followed by a fresh key for the same members")
                    }
                }
            }
            if transition.transitionHash == trustedHash { trustedSeen = true }
            previous = transition
        }
        guard trustedSeen, let head = previous else {
            throw ProtocolError.crypto("previously trusted group transition is missing")
        }
        return head
    }

    static func verifyKeyPackageDigest(_ package: KeyPackage, transition: GroupKeyRecord) throws {
        guard let expected = transition.packageDigests.first(where: { $0.deviceID == package.deviceID }),
              expected.sha256 == (try groupKeyPackageDigest(package)) else {
            throw ProtocolError.crypto("group key package digest is invalid")
        }
    }

    static func groupKeyPackageDigest(_ package: KeyPackage) throws -> String {
        hashText([
            "notify.guru/group-key-package/v1", package.deviceID, package.ephemeralPublicKey,
            package.nonce, package.ciphertext,
        ].joined(separator: "\n"))
    }

    static func deviceRequestBindingHash(
        requestID: String, deviceID: String, signingPublicKey: String,
        accessHash: String, encryptionPublicKey: String, protocolVersion: Int
    ) -> String {
        hashText([
            "notify.guru/device-request-binding/v1", requestID, deviceID, signingPublicKey,
            accessHash, encryptionPublicKey, String(protocolVersion),
        ].joined(separator: "\n"))
    }

    static func deviceApprovalProof(
        authSecret: String, requestID: String, groupID: String, transitionHash: String
    ) throws -> String {
        let transcript = ["notify.guru/device-approval/v1", requestID, groupID, transitionHash].joined(separator: "\n")
        return Base64URL.encode(Data(HMAC<SHA256>.authenticationCode(
            for: Data(transcript.utf8), using: SymmetricKey(data: try Base64URL.decode(authSecret))
        )))
    }

    static func verifyDeviceApprovalProof(
        authSecret: String, requestID: String, groupID: String, transitionHash: String, proof: String
    ) throws -> Bool {
        let transcript = ["notify.guru/device-approval/v1", requestID, groupID, transitionHash].joined(separator: "\n")
        return HMAC<SHA256>.isValidAuthenticationCode(
            try Base64URL.decode(proof), authenticating: Data(transcript.utf8),
            using: SymmetricKey(data: try Base64URL.decode(authSecret))
        )
    }

    static func pushTranscript(deviceID: String, token: String, environment: PushEnvironment) -> String {
        ["notify.guru/device-push/v1", deviceID, token, environment.rawValue].joined(separator: "\n")
    }

    static func signDevice(identity: DeviceIdentity, transcript: String) throws -> String {
        let key = try P256.Signing.PrivateKey(rawRepresentation: identity.signingPrivateKey)
        return Base64URL.encode(try key.signature(for: Data(transcript.utf8)).rawRepresentation)
    }

    static func hashToken(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func verifySignature(publicKey: String, signature: String, transcript: String) throws -> Bool {
        let key = try P256.Signing.PublicKey(x963Representation: Base64URL.decode(publicKey))
        let value = try P256.Signing.ECDSASignature(rawRepresentation: Base64URL.decode(signature))
        return key.isValidSignature(value, for: Data(transcript.utf8))
    }

    private static func hashText(_ value: String) -> String {
        SHA256.hash(data: Data(value.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private static func canonicalLess(_ left: String, _ right: String) -> Bool {
        left.utf8.lexicographicallyPrecedes(right.utf8)
    }

    static func decryptEvent(session: SessionRecord, envelope: EventEnvelope) throws -> SessionEvent {
        guard let key = session.keys[String(envelope.keyTimestamp)] else {
            throw ProtocolError.crypto("session key is unavailable for event timestamp")
        }
        let aad = Data("notify.guru/v\(session.protocolVersion)/event/\(session.sessionID)/\(session.groupID)/\(envelope.keyTimestamp)/\(envelope.eventID)".utf8)
        return try EventDecoder.decode(try open(payload: envelope.ciphertext, nonce: envelope.nonce, key: key, aad: aad))
    }

    static func encryptResponse(session: SessionRecord, timestamp: Int64, responseID: String, requestID: String, optionID: String, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("response key is unavailable") }
        let response = ResponsePayload(id: responseID, type: "response", requestID: requestID, optionID: optionID, createdAt: createdAt)

        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    static func encryptDismiss(session: SessionRecord, timestamp: Int64, responseID: String, eventID: String, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("dismiss key is unavailable") }
        let response = DismissPayload(id: responseID, type: "dismiss", eventID: eventID, createdAt: createdAt)
        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    static func encryptLegacyRequestDismiss(session: SessionRecord, timestamp: Int64, responseID: String, requestID: String, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("dismiss key is unavailable") }
        let response = LegacyDismissPayload(id: responseID, type: "dismiss", requestID: requestID, createdAt: createdAt)
        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    static func encryptFeedback(session: SessionRecord, timestamp: Int64, responseID: String, message: String?, attachment: AttachmentManifest?, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("feedback key is unavailable") }
        let response = FeedbackPayload(id: responseID, type: "feedback", message: message, attachment: attachment, createdAt: createdAt)
        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    private static func encryptResponsePayload<T: Encodable>(_ response: T, session: SessionRecord, timestamp: Int64, responseID: String, key: Data) throws -> EncryptedPayload {
        let aad = Data("notify.guru/v\(session.protocolVersion)/response/\(session.sessionID)/\(session.groupID)/\(timestamp)/\(responseID)".utf8)
        let nonceData = try randomData(count: 12)
        let sealed = try AES.GCM.seal(
            JSONEncoder().encode(response), using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonceData), authenticating: aad
        )
        return EncryptedPayload(nonce: Base64URL.encode(nonceData), ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag))
    }

    static func randomToken() throws -> String { Base64URL.encode(try randomData(count: 32)) }
    static func randomID() throws -> String { Base64URL.encode(try randomData(count: 18)) }

    static func encryptAttachment(
        groupKey: GroupKey,
        creatorPublicKey: String,
        sessionID: String,
        groupID: String,
        responseID: String,
        attachmentID: String,
        jpeg: Data,
        width: Int,
        height: Int
    ) throws -> EncryptedAttachment {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: groupKey.privateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(creatorPublicKey))
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let info = Data("notify.guru/attachment/v4\n\(sessionID)\n\(groupID)\n\(groupKey.timestamp)\n\(responseID)\n\(attachmentID)".utf8)
        let key = secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32)
        let nonceData = try randomData(count: 12)
        let aad = Data("notify.guru/v4/attachment/\(sessionID)/\(groupID)/\(groupKey.timestamp)/\(responseID)/\(attachmentID)".utf8)
        let sealed = try AES.GCM.seal(jpeg, using: key, nonce: try AES.GCM.Nonce(data: nonceData), authenticating: aad)
        let ciphertext = sealed.ciphertext + sealed.tag
        let manifest = AttachmentManifest(
            id: attachmentID, kind: "image", mediaType: "image/jpeg", byteLength: Int64(jpeg.count),
            width: width, height: height, nonce: Base64URL.encode(nonceData),
            ciphertextLength: Int64(ciphertext.count), ciphertextSha256: SHA256.hash(data: ciphertext).map { String(format: "%02x", $0) }.joined()
        )
        return EncryptedAttachment(manifest: manifest, ciphertext: ciphertext)
    }

    private static func packageContext(groupID: String, publicKey: String, deviceID: String) -> String {
        "notify.guru/group-package/v2\n\(groupID)\n\(publicKey)\n\(deviceID)"
    }

    private static func open(payload: String, nonce: String, key: Data, aad: Data) throws -> Data {
        let combined = try Base64URL.decode(payload)
        guard combined.count >= 16 else { throw ProtocolError.crypto("ciphertext is shorter than its tag") }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: try Base64URL.decode(nonce)),
            ciphertext: combined.dropLast(16), tag: combined.suffix(16)
        )
        return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad)
    }

    private static func symmetricData(_ key: SymmetricKey) -> Data { key.withUnsafeBytes { Data($0) } }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else { throw ProtocolError.crypto("secure random generator returned OSStatus \(status)") }
        return data
    }
}

struct EncryptedPayload: Equatable { let nonce: String; let ciphertext: String }

struct AttachmentManifest: Codable, Equatable {
    let id: String
    let kind: String
    let mediaType: String
    let byteLength: Int64
    let width: Int
    let height: Int
    let nonce: String
    let ciphertextLength: Int64
    let ciphertextSha256: String
}

struct EncryptedAttachment: Equatable {
    let manifest: AttachmentManifest
    let ciphertext: Data
}

private struct ResponsePayload: Encodable {
    let id: String
    let type: String
    let requestID: String
    let optionID: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case type
        case requestID = "requestId"
        case optionID = "optionId"
        case createdAt
    }
}

private struct FeedbackPayload: Encodable {
    let id: String
    let type: String
    let message: String?
    let attachment: AttachmentManifest?
    let createdAt: String
}

private struct DismissPayload: Encodable {
    let id: String
    let type: String
    let eventID: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case type
        case eventID = "eventId"
        case createdAt
    }
}

private struct LegacyDismissPayload: Encodable {
    let id: String
    let type: String
    let requestID: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case type
        case requestID = "requestId"
        case createdAt
    }
}
