import CryptoKit
import Foundation
import Security

enum CryptoEngine {
    private static let keyInfo = Data("notify.guru/session/v1".utf8)

    static func createIdentity() throws -> DeviceIdentity {
        let privateKey = P256.KeyAgreement.PrivateKey()
        return DeviceIdentity(groupID: try randomID(), privateKey: privateKey.rawRepresentation)
    }

    static func publicKey(for identity: DeviceIdentity) throws -> String {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.privateKey)
        return Base64URL.encode(privateKey.publicKey.x963Representation)
    }

    static func deriveSessionKey(identity: DeviceIdentity, creatorPublicKey: String, sessionID: String) throws -> Data {
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: identity.privateKey)
        let publicKeyData = try Base64URL.decode(creatorPublicKey)
        let publicKey = try P256.KeyAgreement.PublicKey(x963Representation: publicKeyData)
        let secret = try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
        let key = secret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(sessionID.utf8),
            sharedInfo: keyInfo,
            outputByteCount: 32
        )
        return key.withUnsafeBytes { bytes in
            Data(bytes: bytes.baseAddress!, count: bytes.count)
        }
    }

    static func pairingProof(
        authSecret: String,
        sessionID: String,
        pairingID: String,
        groupID: String,
        groupPublicKey: String
    ) throws -> String {
        let secret = try Base64URL.decode(authSecret)
        let transcript = "v1\n\(sessionID)\n\(pairingID)\n\(groupID)\n\(groupPublicKey)"
        let authentication = HMAC<SHA256>.authenticationCode(
            for: Data(transcript.utf8),
            using: SymmetricKey(data: secret)
        )
        return Base64URL.encode(Data(authentication))
    }

    static func hashToken(_ token: String) -> String {
        SHA256.hash(data: Data(token.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    static func decryptEvent(session: SessionRecord, envelope: EventEnvelope) throws -> SessionEvent {
        let nonceData = try Base64URL.decode(envelope.nonce)
        guard nonceData.count == 12 else {
            throw ProtocolError.crypto("event nonce must contain 12 bytes")
        }
        let combined = try Base64URL.decode(envelope.ciphertext)
        guard combined.count >= 16 else {
            throw ProtocolError.crypto("event ciphertext is shorter than its authentication tag")
        }
        let ciphertext = combined.dropLast(16)
        let tag = combined.suffix(16)
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonceData),
            ciphertext: ciphertext,
            tag: tag
        )
        let aad = Data("notify.guru/v1/event/\(session.sessionID)/\(session.groupID)/\(envelope.eventID)".utf8)
        let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: session.sharedKey), authenticating: aad)
        return try EventDecoder.decode(plaintext)
    }

    static func encryptResponse(
        session: SessionRecord,
        responseID: String,
        requestID: String,
        optionID: String,
        createdAt: String
    ) throws -> EncryptedPayload {
        let response = ResponsePayload(
            id: responseID,
            requestID: requestID,
            optionID: optionID,
            createdAt: createdAt
        )
        let plaintext = try JSONEncoder().encode(response)
        let nonceData = try randomData(count: 12)
        let nonce = try AES.GCM.Nonce(data: nonceData)
        let aad = Data("notify.guru/v1/response/\(session.sessionID)/\(session.groupID)/\(responseID)".utf8)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: session.sharedKey),
            nonce: nonce,
            authenticating: aad
        )
        return EncryptedPayload(
            nonce: Base64URL.encode(nonceData),
            ciphertext: Base64URL.encode(sealed.ciphertext + sealed.tag)
        )
    }

    static func randomToken() throws -> String {
        Base64URL.encode(try randomData(count: 32))
    }

    static func randomID() throws -> String {
        Base64URL.encode(try randomData(count: 18))
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
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
