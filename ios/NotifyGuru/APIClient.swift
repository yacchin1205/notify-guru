import Foundation

struct EventEnvelope: Equatable {
    let sequence: Int64
    let eventID: String
    let itemID: String?
    let groupID: String
    let keyTimestamp: Int64
    let nonce: String
    let ciphertext: String
    let createdAt: Int64
}

struct EventsResult: Equatable { let events: [EventEnvelope]; let activeItemIDs: [String]; let attention: Bool; let expiresAt: Int64 }

enum DeviceRequestStatus: Equatable {
    case waiting(expiresAt: Int64)
    case expired(expiresAt: Int64)
    case approved(groupID: String, expiresAt: Int64)
}

struct APIClient {
    private let baseURL = URL(string: "https://notify.guru")!
    private let maximumResponseBytes = 2 * 1024 * 1024
    private let session: URLSession

    init(session: URLSession = .shared) { self.session = session }

    func registerDevice(identity: DeviceIdentity) async throws -> String {
        let signingPublicKey = try CryptoEngine.signingPublicKey(for: identity)
        let nonce = try CryptoEngine.randomToken()
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.deviceCreateTranscript(signingPublicKey: signingPublicKey, nonce: nonce)
        )
        let data = try await request(method: "POST", path: "/api/devices", token: nil, body: try encode([
            "signingPublicKey": signingPublicKey, "nonce": nonce, "signature": signature,
        ]), expectedStatus: 201)
        return try text(object(data, keys: ["deviceId"]), "deviceId")
    }

    func registerPushToken(_ token: String, environment: PushEnvironment, identity: DeviceIdentity) async throws {
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.pushTranscript(deviceID: identity.deviceID, token: token, environment: environment)
        )
        let data = try await request(
            method: "PUT", path: "/api/devices/\(identity.deviceID)/push", token: nil,
            body: try encode(["token": token, "environment": environment.rawValue, "signature": signature]), expectedStatus: 200
        )
        guard try object(data, keys: ["updated"])["updated"] as? Bool == true else {
            throw ProtocolError.invalidResponse("push token update was not confirmed")
        }
    }

    func createGroup(groupID: String, identity: DeviceIdentity) async throws {
        let accessHash = CryptoEngine.hashToken(identity.accessToken)
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.groupCreateTranscript(groupID: groupID, identity: identity, accessHash: accessHash)
        )
        let body: [String: Any] = [
            "groupId": groupID, "deviceId": identity.deviceID, "deviceAccessTokenHash": accessHash,
            "deviceEncryptionPublicKey": try CryptoEngine.encryptionPublicKey(for: identity), "deviceSignature": signature,
        ]
        let data = try await request(method: "POST", path: "/api/groups", token: nil, body: try encode(body), expectedStatus: 201)
        let fields = try object(data, keys: ["created", "groupId"])
        guard fields["created"] as? Bool == true, try text(fields, "groupId") == groupID else {
            throw ProtocolError.invalidResponse("group creation was not confirmed")
        }
    }

    func groupState(identity: DeviceIdentity) async throws -> DeviceGroupStateResult {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        let path = pathWithQuery("/api/groups/\(group.groupID)/state", ["deviceId": identity.deviceID, "protocolVersion": "4"])
        let data = try await request(method: "GET", path: path, token: identity.accessToken, body: nil, expectedStatus: 200)
        _ = try object(data, keys: ["groupId", "members", "keys", "packages", "sessions"])
        let result = try JSONDecoder().decode(DeviceGroupStateResult.self, from: data)
        guard result.groupID == group.groupID else { throw ProtocolError.invalidResponse("group state ID mismatch") }
        return result
    }

    func registerGroupKey(identity: DeviceIdentity, key: GroupKey, recreated: Bool, members: [GroupDevice]) async throws -> Int64 {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        let packages = try members.map {
            try CryptoEngine.createKeyPackage(groupID: group.groupID, key: key, deviceID: $0.deviceID, encryptionPublicKey: $0.encryptionPublicKey)
        }
        let memberIDs = members.map(\.deviceID)
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.groupKeyRegisterTranscript(
                groupID: group.groupID, actorDeviceID: identity.deviceID, publicKey: key.publicKey,
                recreated: recreated, members: memberIDs, packages: packages
            )
        )
        let body = RegisterGroupKeyRequest(
            publicKey: key.publicKey, recreated: recreated, members: memberIDs,
            packages: packages, actorSignature: signature
        )
        let path = pathWithQuery("/api/groups/\(group.groupID)/keys", ["deviceId": identity.deviceID])
        let data = try await request(method: "POST", path: path, token: identity.accessToken, body: try JSONEncoder().encode(body), expectedStatus: 201)
        return try integer(object(data, keys: ["timestamp"]), "timestamp")
    }

    func createDeviceRequest(identity: DeviceIdentity, requestID: String) async throws -> DeviceRequestRecord {
        let accessHash = CryptoEngine.hashToken(identity.accessToken)
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.deviceRequestTranscript(requestID: requestID, identity: identity, accessHash: accessHash, protocolVersion: 4)
        )
        let body: [String: Any] = [
            "requestId": requestID, "deviceId": identity.deviceID, "deviceAccessTokenHash": accessHash,
            "deviceEncryptionPublicKey": try CryptoEngine.encryptionPublicKey(for: identity), "deviceSignature": signature,
            "protocolVersion": 4,
        ]
        let data = try await request(method: "POST", path: "/api/device-requests", token: nil, body: try encode(body), expectedStatus: 201)
        let fields = try object(data, keys: ["requestId", "expiresAt"])
        guard try text(fields, "requestId") == requestID else {
            throw ProtocolError.invalidResponse("the server response did not match the add-to-group link")
        }
        return DeviceRequestRecord(requestID: requestID, expiresAt: try integer(fields, "expiresAt"))
    }

    func deviceRequestStatus(identity: DeviceIdentity, requestID: String) async throws -> DeviceRequestStatus {
        let signature = try CryptoEngine.signDevice(
            identity: identity, transcript: CryptoEngine.deviceRequestReadTranscript(requestID: requestID, deviceID: identity.deviceID)
        )
        let path = pathWithQuery("/api/device-requests/\(requestID)", ["deviceId": identity.deviceID])
        let data = try await request(method: "GET", path: path, token: signature, body: nil, expectedStatus: 200)
        let raw = try JSONSerialization.jsonObject(with: data)
        guard let fields = raw as? [String: Any], let status = fields["status"] as? String else {
            throw ProtocolError.invalidResponse("the server returned an invalid add-to-group status")
        }
        switch status {
        case "waiting":
            try requireKeys(fields, ["status", "expiresAt"])
            return .waiting(expiresAt: try integer(fields, "expiresAt"))
        case "expired":
            try requireKeys(fields, ["status", "expiresAt"])
            return .expired(expiresAt: try integer(fields, "expiresAt"))
        case "approved":
            try requireKeys(fields, ["status", "groupId", "expiresAt"])
            return .approved(groupID: try text(fields, "groupId"), expiresAt: try integer(fields, "expiresAt"))
        default: throw ProtocolError.invalidResponse("the server returned an unknown add-to-group status")
        }
    }

    func approveDeviceRequest(identity: DeviceIdentity, requestID: String) async throws {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        let path = pathWithQuery("/api/groups/\(group.groupID)/device-requests/\(requestID)/approve", ["deviceId": identity.deviceID])
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.groupDeviceApproveTranscript(
                groupID: group.groupID, actorDeviceID: identity.deviceID, requestID: requestID
            )
        )
        let data = try await request(
            method: "POST", path: path, token: identity.accessToken,
            body: try encode(["actorSignature": signature]), expectedStatus: 200
        )
        guard try object(data, keys: ["approved", "deviceId", "approvedByDeviceId"])["approved"] as? Bool == true else {
            throw ProtocolError.invalidResponse("the server did not confirm that the device was added to the group")
        }
    }

    func removeDevice(identity: DeviceIdentity, deviceID: String) async throws {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        let path = pathWithQuery("/api/groups/\(group.groupID)/devices/\(deviceID)", ["deviceId": identity.deviceID])
        let signature = try CryptoEngine.signDevice(
            identity: identity,
            transcript: CryptoEngine.groupDeviceRemoveTranscript(
                groupID: group.groupID, actorDeviceID: identity.deviceID, deviceID: deviceID
            )
        )
        let data = try await request(
            method: "DELETE", path: path, token: identity.accessToken,
            body: try encode(["actorSignature": signature]), expectedStatus: 200
        )
        guard try object(data, keys: ["removed"])["removed"] as? Bool == true else {
            throw ProtocolError.invalidResponse("device removal was not confirmed")
        }
    }

    func join(_ pairing: PairingLink, identity: DeviceIdentity, key: GroupKey) async throws -> Int64 {
        guard let group = identity.group else { throw ProtocolError.invalidPairingLink("device group is not ready") }
        let proof = try CryptoEngine.pairingProof(
            authSecret: pairing.authSecret, protocolVersion: pairing.protocolVersion,
            sessionID: pairing.sessionID, pairingID: pairing.pairingID,
            groupID: group.groupID, timestamp: key.timestamp, groupPublicKey: key.publicKey
        )
        let body = JoinRequest(
            pairingID: pairing.pairingID, pairingToken: pairing.pairingToken, groupID: group.groupID,
            deviceID: identity.deviceID, deviceAccessToken: identity.accessToken, keyTimestamp: key.timestamp,
            groupPublicKey: key.publicKey, proof: proof
        )
        let data = try await request(method: "POST", path: "/api/sessions/\(pairing.sessionID)/join", token: nil, body: try JSONEncoder().encode(body), expectedStatus: 201)
        let fields = try object(data, keys: ["joined", "expiresAt"])
        guard fields["joined"] as? Bool == true else { throw ProtocolError.invalidResponse("join was not confirmed") }
        return try integer(fields, "expiresAt")
    }

    func events(for record: SessionRecord, identity: DeviceIdentity) async throws -> EventsResult {
        let path = pathWithQuery("/api/sessions/\(record.sessionID)/events", [
            "groupId": record.groupID, "deviceId": identity.deviceID, "after": String(record.cursor),
            "includeActive": "1", "includeAttention": "1",
        ])
        let data = try await request(method: "GET", path: path, token: identity.accessToken, body: nil, expectedStatus: 200)
        let fields = try object(data, keys: ["events", "activeItemIds", "attention", "expiresAt"])
        guard let eventObjects = fields["events"] as? [[String: Any]] else { throw ProtocolError.invalidResponse("events must be objects") }
        let events = try eventObjects.map { event in
            try requireKeys(event, ["sequence", "eventId", "itemId", "groupId", "keyTimestamp", "nonce", "ciphertext", "createdAt"])
            guard event["itemId"] is NSNull || event["itemId"] is String else {
                throw ProtocolError.invalidResponse("event itemId must be a string or null")
            }
            let envelope = EventEnvelope(
                sequence: try integer(event, "sequence"), eventID: try text(event, "eventId"),
                itemID: event["itemId"] as? String,
                groupID: try text(event, "groupId"), keyTimestamp: try integer(event, "keyTimestamp"),
                nonce: try text(event, "nonce"), ciphertext: try text(event, "ciphertext"), createdAt: try integer(event, "createdAt")
            )
            guard envelope.groupID == record.groupID else { throw ProtocolError.invalidResponse("event group mismatch") }
            return envelope
        }
        guard let activeItemIDs = fields["activeItemIds"] as? [String] else {
            throw ProtocolError.invalidResponse("activeItemIds must be strings")
        }
        guard let attention = fields["attention"] as? Bool else {
            throw ProtocolError.invalidResponse("attention must be a boolean")
        }
        return EventsResult(events: events, activeItemIDs: activeItemIDs, attention: attention, expiresAt: try integer(fields, "expiresAt"))
    }

    func setAttention(session record: SessionRecord, identity: DeviceIdentity, attention: Bool) async throws {
        let data = try await request(
            method: "PUT", path: "/api/sessions/\(record.sessionID)/attention", token: identity.accessToken,
            body: try encode(["groupId": record.groupID, "deviceId": identity.deviceID, "attention": attention]),
            expectedStatus: 200
        )
        guard try object(data, keys: ["attention", "expiresAt"])["attention"] as? Bool == attention else {
            throw ProtocolError.invalidResponse("attention change was not confirmed")
        }
    }

    func postResponse(session record: SessionRecord, identity: DeviceIdentity, timestamp: Int64, responseID: String, itemID: String?, attachmentID: String? = nil, payload: EncryptedPayload) async throws -> Int64 {
        let body = PostResponseRequest(
            responseID: responseID, itemID: itemID, groupID: record.groupID, deviceID: identity.deviceID,
            keyTimestamp: timestamp, nonce: payload.nonce, ciphertext: payload.ciphertext, attachmentID: attachmentID
        )
        let data = try await request(
            method: "POST", path: "/api/sessions/\(record.sessionID)/responses", token: identity.accessToken,
            body: try JSONEncoder().encode(body), expectedStatus: 201
        )
        return try integer(object(data, keys: ["expiresAt"]), "expiresAt")
    }

    func reserveAttachment(
        session record: SessionRecord,
        identity: DeviceIdentity,
        timestamp: Int64,
        responseID: String,
        attachment: EncryptedAttachment
    ) async throws -> AttachmentReservation {
        let body: [String: Any] = [
            "attachmentId": attachment.manifest.id,
            "responseId": responseID,
            "groupId": record.groupID,
            "deviceId": identity.deviceID,
            "keyTimestamp": timestamp,
            "ciphertextLength": attachment.manifest.ciphertextLength,
            "ciphertextSha256": attachment.manifest.ciphertextSha256,
        ]
        let data = try await request(
            method: "POST", path: "/api/sessions/\(record.sessionID)/attachments", token: identity.accessToken,
            body: try encode(body), expectedStatus: 201
        )
        let fields = try object(data, keys: ["attachmentId", "uploadToken", "maxCiphertextBytes", "uploadExpiresAt"])
        guard try text(fields, "attachmentId") == attachment.manifest.id else {
            throw ProtocolError.invalidResponse("attachment reservation ID mismatch")
        }
        return AttachmentReservation(
            uploadToken: try text(fields, "uploadToken"),
            maximumCiphertextBytes: try integer(fields, "maxCiphertextBytes"),
            expiresAt: try integer(fields, "uploadExpiresAt")
        )
    }

    func uploadAttachment(session record: SessionRecord, attachment: EncryptedAttachment, reservation: AttachmentReservation) async throws {
        guard attachment.manifest.ciphertextLength <= reservation.maximumCiphertextBytes else {
            throw ProtocolError.invalidResponse("attachment exceeds the current service limit")
        }
        guard let url = URL(string: "/api/sessions/\(record.sessionID)/attachments/\(attachment.manifest.id)", relativeTo: baseURL)?.absoluteURL else {
            throw ProtocolError.invalidResponse("invalid attachment upload URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.timeoutInterval = 20
        request.httpBody = attachment.ciphertext
        request.setValue("Bearer \(reservation.uploadToken)", forHTTPHeaderField: "Authorization")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        let (data, response) = try await self.session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ProtocolError.invalidResponse("API did not return HTTP") }
        guard data.count <= maximumResponseBytes else { throw ProtocolError.invalidResponse("body exceeds \(maximumResponseBytes) bytes") }
        guard http.statusCode == 200 else { throw try apiError(status: http.statusCode, data: data) }
        let fields = try object(data, keys: ["uploaded"])
        guard fields["uploaded"] as? Bool == true else { throw ProtocolError.invalidResponse("attachment upload was not confirmed") }
    }

    private func pathWithQuery(_ path: String, _ values: [String: String]) -> String {
        var components = URLComponents(); components.path = path
        components.queryItems = values.sorted { $0.key < $1.key }.map { URLQueryItem(name: $0.key, value: $0.value) }
        return components.string!
    }

    private func request(method: String, path: String, token: String?, body: Data?, expectedStatus: Int) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL, url.scheme == "https", url.host == baseURL.host else {
            throw ProtocolError.invalidResponse("invalid API URL")
        }
        var request = URLRequest(url: url); request.httpMethod = method; request.timeoutInterval = 20; request.httpBody = body
        if let token { request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw ProtocolError.invalidResponse("API did not return HTTP") }
        guard data.count <= maximumResponseBytes else { throw ProtocolError.invalidResponse("body exceeds \(maximumResponseBytes) bytes") }
        guard http.statusCode == expectedStatus else { throw try apiError(status: http.statusCode, data: data) }
        return data
    }

    private func apiError(status: Int, data: Data) throws -> APIError {
        let fields = try object(data, keys: ["error", "message"])
        return APIError(status: status, code: try text(fields, "error"), message: try text(fields, "message"))
    }

    private func encode(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value) }

    private func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        guard let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw ProtocolError.invalidResponse("body must be an object")
        }
        try requireKeys(fields, keys); return fields
    }

    private func requireKeys(_ fields: [String: Any], _ expected: Set<String>) throws {
        guard Set(fields.keys) == expected else { throw ProtocolError.invalidResponse("object fields do not match the protocol") }
    }

    private func text(_ fields: [String: Any], _ name: String) throws -> String {
        guard let value = fields[name] as? String, !value.isEmpty else { throw ProtocolError.invalidResponse("\(name) must be text") }
        return value
    }

    private func integer(_ fields: [String: Any], _ name: String) throws -> Int64 {
        guard let number = fields[name] as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw ProtocolError.invalidResponse("\(name) must be an integer")
        }
        let value = number.int64Value
        guard value >= 0, NSNumber(value: value) == number else { throw ProtocolError.invalidResponse("\(name) must be non-negative") }
        return value
    }
}

struct APIError: LocalizedError, Equatable {
    let status: Int; let code: String; let message: String
    var errorDescription: String? { "notify.guru API: \(code) (\(status)): \(message)" }
}

private struct RegisterGroupKeyRequest: Encodable {
    let publicKey: String; let recreated: Bool; let members: [String]; let packages: [KeyPackage]; let actorSignature: String
}

private struct JoinRequest: Encodable {
    let pairingID: String; let pairingToken: String; let groupID: String; let deviceID: String
    let deviceAccessToken: String; let keyTimestamp: Int64; let groupPublicKey: String; let proof: String
    enum CodingKeys: String, CodingKey {
        case pairingID = "pairingId"; case pairingToken; case groupID = "groupId"; case deviceID = "deviceId"
        case deviceAccessToken, keyTimestamp, groupPublicKey, proof
    }
}

private struct PostResponseRequest: Encodable {
    let responseID: String; let itemID: String?; let groupID: String; let deviceID: String; let keyTimestamp: Int64
    let nonce: String; let ciphertext: String; let attachmentID: String?
    enum CodingKeys: String, CodingKey {
        case responseID = "responseId"; case itemID = "itemId"; case groupID = "groupId"; case deviceID = "deviceId"
        case keyTimestamp, nonce, ciphertext; case attachmentID = "attachmentId"
    }
}

struct AttachmentReservation: Equatable {
    let uploadToken: String
    let maximumCiphertextBytes: Int64
    let expiresAt: Int64
}
