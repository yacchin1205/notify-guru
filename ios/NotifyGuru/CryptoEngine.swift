import CryptoKit
import Foundation
import Security

struct KeyPackage: Codable, Equatable {
    let generation: Int64
    let deviceID: String
    let ephemeralPublicKey: String
    let nonce: String
    let ciphertext: String

    enum CodingKeys: String, CodingKey {
        case generation
        case deviceID = "deviceId"
        case ephemeralPublicKey
        case nonce
        case ciphertext
    }
}

struct GenerationTransition: Codable, Equatable {
    let revision: Int64
    let previousGeneration: Int64
    let generation: Int64
    let generationPublicKey: String
    let action: String
    let actorDeviceID: String
    let targetDeviceID: String
    let packagesHash: String
    let groupSignature: String
    let deviceSignature: String
    let createdAt: Int64

    enum CodingKeys: String, CodingKey {
        case revision, previousGeneration, generation, generationPublicKey, action
        case actorDeviceID = "actorDeviceId"
        case targetDeviceID = "targetDeviceId"
        case packagesHash, groupSignature, deviceSignature, createdAt
    }
}

enum CryptoEngine {
    static func createIdentity() throws -> DeviceIdentity {
        DeviceIdentity(
            deviceID: try randomID(),
            accessToken: try randomToken(),
            encryptionPrivateKey: P256.KeyAgreement.PrivateKey().rawRepresentation,
            signingPrivateKey: P256.Signing.PrivateKey().rawRepresentation,
            group: nil,
            pendingInvitation: nil,
            invitations: [:]
        )
    }

    static func encryptionPublicKey(for identity: DeviceIdentity) throws -> String {
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.encryptionPrivateKey)
        return Base64URL.encode(key.publicKey.x963Representation)
    }

    static func signingPublicKey(for identity: DeviceIdentity) throws -> String {
        let key = try P256.Signing.PrivateKey(rawRepresentation: identity.signingPrivateKey)
        return Base64URL.encode(key.publicKey.x963Representation)
    }

    static func createGeneration(_ generation: Int64) -> GenerationKey {
        let key = P256.KeyAgreement.PrivateKey()
        return GenerationKey(
            generation: generation,
            publicKey: Base64URL.encode(key.publicKey.x963Representation),
            privateKey: key.rawRepresentation
        )
    }

    static func createKeyPackage(
        groupID: String,
        generation: GenerationKey,
        deviceID: String,
        encryptionPublicKey: String
    ) throws -> KeyPackage {
        let ephemeral = P256.KeyAgreement.PrivateKey()
        let recipient = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(encryptionPublicKey))
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
        let context = packageContext(groupID: groupID, generation: generation.generation, deviceID: deviceID)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(context.utf8),
            outputByteCount: 32
        )
        let plaintext = Data([
            "notify.guru/group-generation-key/v1",
            String(generation.generation),
            generation.publicKey,
            Base64URL.encode(generation.privateKey),
        ].joined(separator: "\n").utf8)
        let nonceData = try randomData(count: 12)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: wrappingKey,
            nonce: try AES.GCM.Nonce(data: nonceData),
            authenticating: Data(context.utf8)
        )
        return KeyPackage(
            generation: generation.generation,
            deviceID: deviceID,
            ephemeralPublicKey: Base64URL.encode(ephemeral.publicKey.x963Representation),
            nonce: Base64URL.encode(nonceData),
            ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag)
        )
    }

    static func openKeyPackage(
        identity: DeviceIdentity,
        groupID: String,
        expectedPublicKey: String?,
        package: KeyPackage
    ) throws -> GenerationKey {
        guard package.deviceID == identity.deviceID else {
            throw ProtocolError.crypto("key package targets another device")
        }
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.encryptionPrivateKey)
        let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(package.ephemeralPublicKey))
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
        let context = packageContext(groupID: groupID, generation: package.generation, deviceID: identity.deviceID)
        let wrappingKey = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(),
            sharedInfo: Data(context.utf8),
            outputByteCount: 32
        )
        let combined = try Base64URL.decode(package.ciphertext)
        guard combined.count >= 16 else { throw ProtocolError.crypto("key package is shorter than its tag") }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: try Base64URL.decode(package.nonce)),
            ciphertext: combined.dropLast(16),
            tag: combined.suffix(16)
        )
        let plaintext = try AES.GCM.open(box, using: wrappingKey, authenticating: Data(context.utf8))
        guard let decoded = String(data: plaintext, encoding: .utf8) else {
            throw ProtocolError.crypto("key package plaintext is not UTF-8")
        }
        let fields = decoded.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard fields.count == 4,
              fields[0] == "notify.guru/group-generation-key/v1",
              let encodedGeneration = Int64(fields[1]) else {
            throw ProtocolError.crypto("key package plaintext has invalid fields")
        }
        let generation = GenerationKey(
            generation: encodedGeneration,
            publicKey: fields[2],
            privateKey: try Base64URL.decode(fields[3])
        )
        guard generation.generation == package.generation,
              expectedPublicKey == nil || generation.publicKey == expectedPublicKey else {
            throw ProtocolError.crypto("key package generation does not match its signed public key")
        }
        let parsed = try P256.KeyAgreement.PrivateKey(rawRepresentation: generation.privateKey)
        guard Base64URL.encode(parsed.publicKey.x963Representation) == generation.publicKey else {
            throw ProtocolError.crypto("generation private and public keys do not match")
        }
        return generation
    }

    static func deriveSessionKey(
        generation: GenerationKey,
        creatorPublicKey: String,
        sessionID: String,
        groupID: String
    ) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: generation.privateKey)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: Base64URL.decode(creatorPublicKey))
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let info = Data("notify.guru/session/v2\n\(sessionID)\n\(groupID)\n\(generation.generation)".utf8)
        return symmetricData(secret.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: info, outputByteCount: 32
        ))
    }

    static func pairingProof(
        authSecret: String,
        sessionID: String,
        pairingID: String,
        groupID: String,
        revision: Int64,
        generation: Int64,
        groupPublicKey: String
    ) throws -> String {
        let transcript = "v2\n\(sessionID)\n\(pairingID)\n\(groupID)\n\(revision)\n\(generation)\n\(groupPublicKey)"
        let authentication = HMAC<SHA256>.authenticationCode(
            for: Data(transcript.utf8), using: SymmetricKey(data: try Base64URL.decode(authSecret))
        )
        return Base64URL.encode(Data(authentication))
    }

    static func groupCreateTranscript(
        groupID: String,
        identity: DeviceIdentity,
        generation: GenerationKey,
        packagesHash: String
    ) throws -> String {
        [
            "notify.guru/group-create/v1", groupID, identity.deviceID,
            try encryptionPublicKey(for: identity), try signingPublicKey(for: identity),
            generation.publicKey, packagesHash,
        ].joined(separator: "\n")
    }

    static func transitionTranscript(groupID: String, transition: GenerationTransition) -> String {
        [
            "notify.guru/group-transition/v1", groupID, String(transition.revision),
            String(transition.previousGeneration), String(transition.generation),
            transition.generationPublicKey, transition.action, transition.actorDeviceID,
            transition.targetDeviceID, transition.packagesHash,
        ].joined(separator: "\n")
    }

    static func signDevice(identity: DeviceIdentity, transcript: String) throws -> String {
        let key = try P256.Signing.PrivateKey(rawRepresentation: identity.signingPrivateKey)
        return Base64URL.encode(try key.signature(for: Data(transcript.utf8)).rawRepresentation)
    }

    static func signGeneration(_ generation: GenerationKey, transcript: String) throws -> String {
        let key = try P256.Signing.PrivateKey(rawRepresentation: generation.privateKey)
        return Base64URL.encode(try key.signature(for: Data(transcript.utf8)).rawRepresentation)
    }

    static func verify(publicKey: String, signature: String, transcript: String) throws -> Bool {
        let key = try P256.Signing.PublicKey(x963Representation: Base64URL.decode(publicKey))
        let value = try P256.Signing.ECDSASignature(rawRepresentation: Base64URL.decode(signature))
        return key.isValidSignature(value, for: Data(transcript.utf8))
    }

    static func hashPackages(_ packages: [KeyPackage]) -> String {
        let canonical = packages.sorted {
            $0.generation == $1.generation ? $0.deviceID < $1.deviceID : $0.generation < $1.generation
        }.map {
            [String($0.generation), $0.deviceID, $0.ephemeralPublicKey, $0.nonce, $0.ciphertext].joined(separator: "\n")
        }.joined(separator: "\n--\n")
        return hashToken(canonical)
    }

    static func verificationCode(invitation: DeviceInvitationRecord, pending: PendingDevice) -> String {
        let transcript = [
            "notify.guru/device-verification/v1", invitation.groupID, invitation.invitationID,
            invitation.invitationToken, pending.deviceID, pending.encryptionPublicKey, pending.signingPublicKey,
        ].joined(separator: "\n")
        let bytes = Array(SHA256.hash(data: Data(transcript.utf8)))
        let value = ((Int(bytes[0]) << 16) | (Int(bytes[1]) << 8) | Int(bytes[2])) % 1_000_000
        return String(format: "%06d", value)
    }

    static func hashToken(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func decryptEvent(session: SessionRecord, envelope: EventEnvelope) throws -> SessionEvent {
        let key: Data
        let aad: Data
        if session.protocolVersion == 2 {
            guard let generation = envelope.generation,
                  let generationKey = session.generationKeys[String(generation)] else {
                throw ProtocolError.crypto("session generation key is unavailable")
            }
            key = generationKey
            aad = Data("notify.guru/v2/event/\(session.sessionID)/\(session.groupID)/\(generation)/\(envelope.eventID)".utf8)
        } else {
            key = session.sharedKey
            aad = Data("notify.guru/v1/event/\(session.sessionID)/\(session.groupID)/\(envelope.eventID)".utf8)
        }
        let nonceData = try Base64URL.decode(envelope.nonce)
        let combined = try Base64URL.decode(envelope.ciphertext)
        guard nonceData.count == 12, combined.count >= 16 else {
            throw ProtocolError.crypto("event envelope has invalid cryptographic lengths")
        }
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonceData),
            ciphertext: combined.dropLast(16),
            tag: combined.suffix(16)
        )
        return try EventDecoder.decode(AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: aad))
    }

    static func encryptResponse(
        session: SessionRecord,
        generation: Int64?,
        responseID: String,
        requestID: String,
        optionID: String,
        createdAt: String
    ) throws -> EncryptedPayload {
        let response = ResponsePayload(id: responseID, requestID: requestID, optionID: optionID, createdAt: createdAt)
        let key: Data
        let aad: Data
        if session.protocolVersion == 2 {
            guard let generation, let generationKey = session.generationKeys[String(generation)] else {
                throw ProtocolError.crypto("response generation key is unavailable")
            }
            key = generationKey
            aad = Data("notify.guru/v2/response/\(session.sessionID)/\(session.groupID)/\(generation)/\(responseID)".utf8)
        } else {
            key = session.sharedKey
            aad = Data("notify.guru/v1/response/\(session.sessionID)/\(session.groupID)/\(responseID)".utf8)
        }
        let nonceData = try randomData(count: 12)
        let sealed = try AES.GCM.seal(
            JSONEncoder().encode(response),
            using: SymmetricKey(data: key),
            nonce: AES.GCM.Nonce(data: nonceData),
            authenticating: aad
        )
        return EncryptedPayload(nonce: Base64URL.encode(nonceData), ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag))
    }

    static func randomToken() throws -> String { Base64URL.encode(try randomData(count: 32)) }
    static func randomID() throws -> String { Base64URL.encode(try randomData(count: 18)) }

    private static func packageContext(groupID: String, generation: Int64, deviceID: String) -> String {
        "notify.guru/group-package/v1\n\(groupID)\n\(generation)\n\(deviceID)"
    }

    private static func symmetricData(_ key: SymmetricKey) -> Data {
        key.withUnsafeBytes { Data($0) }
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        guard status == errSecSuccess else {
            throw ProtocolError.crypto("secure random generator returned OSStatus \(status)")
        }
        return data
    }
}

struct EncryptedPayload: Equatable {
    let nonce: String
    let ciphertext: String
}

private struct ResponsePayload: Encodable {
    let id: String
    let requestID: String
    let optionID: String
    let createdAt: String

    enum CodingKeys: String, CodingKey {
        case id
        case requestID = "requestId"
        case optionID = "optionId"
        case createdAt
    }
}
