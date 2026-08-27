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
        let key = GroupKey(timestamp: record.timestamp, publicKey: fields[1], privateKey: try Base64URL.decode(fields[2]))
        let parsed = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.privateKey)
        guard Base64URL.encode(parsed.publicKey.x963Representation) == key.publicKey else {
            throw ProtocolError.crypto("group private and public keys do not match")
        }
        return key
    }

    static func deriveSessionKey(key: GroupKey, creatorPublicKey: String, sessionID: String, groupID: String) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: key.privateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(creatorPublicKey))
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let info = Data("notify.guru/session/v3\n\(sessionID)\n\(groupID)\n\(key.timestamp)".utf8)
        return symmetricData(secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32))
    }

    static func pairingProof(authSecret: String, sessionID: String, pairingID: String, groupID: String, timestamp: Int64, groupPublicKey: String) throws -> String {
        let transcript = "v3\n\(sessionID)\n\(pairingID)\n\(groupID)\n\(timestamp)\n\(groupPublicKey)"
        let authentication = HMAC<SHA256>.authenticationCode(
            for: Data(transcript.utf8), using: SymmetricKey(data: try Base64URL.decode(authSecret))
        )
        return Base64URL.encode(Data(authentication))
    }

    static func deviceCreateTranscript(signingPublicKey: String, nonce: String) -> String {
        ["notify.guru/device-create/v1", signingPublicKey, nonce].joined(separator: "\n")
    }

    static func groupCreateTranscript(groupID: String, identity: DeviceIdentity, accessHash: String) throws -> String {
        ["notify.guru/group-create/v2", groupID, identity.deviceID, accessHash, try encryptionPublicKey(for: identity)].joined(separator: "\n")
    }

    static func deviceRequestTranscript(requestID: String, identity: DeviceIdentity, accessHash: String) throws -> String {
        ["notify.guru/device-request/v1", requestID, identity.deviceID, accessHash, try encryptionPublicKey(for: identity)].joined(separator: "\n")
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

    static func decryptEvent(session: SessionRecord, envelope: EventEnvelope) throws -> SessionEvent {
        guard let key = session.keys[String(envelope.keyTimestamp)] else {
            throw ProtocolError.crypto("session key is unavailable for event timestamp")
        }
        let aad = Data("notify.guru/v3/event/\(session.sessionID)/\(session.groupID)/\(envelope.keyTimestamp)/\(envelope.eventID)".utf8)
        return try EventDecoder.decode(try open(payload: envelope.ciphertext, nonce: envelope.nonce, key: key, aad: aad))
    }

    static func encryptResponse(session: SessionRecord, timestamp: Int64, responseID: String, requestID: String, optionID: String, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("response key is unavailable") }
        let response = ResponsePayload(id: responseID, type: "response", requestID: requestID, optionID: optionID, createdAt: createdAt)

        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    static func encryptFeedback(session: SessionRecord, timestamp: Int64, responseID: String, message: String, createdAt: String) throws -> EncryptedPayload {
        guard let key = session.keys[String(timestamp)] else { throw ProtocolError.crypto("feedback key is unavailable") }
        let response = FeedbackPayload(id: responseID, type: "feedback", message: message, createdAt: createdAt)
        return try encryptResponsePayload(response, session: session, timestamp: timestamp, responseID: responseID, key: key)
    }

    private static func encryptResponsePayload<T: Encodable>(_ response: T, session: SessionRecord, timestamp: Int64, responseID: String, key: Data) throws -> EncryptedPayload {
        let aad = Data("notify.guru/v3/response/\(session.sessionID)/\(session.groupID)/\(timestamp)/\(responseID)".utf8)
        let nonceData = try randomData(count: 12)
        let sealed = try AES.GCM.seal(
            JSONEncoder().encode(response), using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonceData), authenticating: aad
        )
        return EncryptedPayload(nonce: Base64URL.encode(nonceData), ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag))
    }

    static func randomToken() throws -> String { Base64URL.encode(try randomData(count: 32)) }
    static func randomID() throws -> String { Base64URL.encode(try randomData(count: 18)) }

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
    let message: String
    let createdAt: String
}
