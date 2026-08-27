import Foundation

struct EventEnvelope: Equatable {
    let sequence: Int64
    let eventID: String
    let groupID: String
    let generation: Int64?
    let nonce: String
    let ciphertext: String
    let createdAt: Int64
}

struct DeviceGroupStateResult: Decodable, Equatable {
    let groupID: String
    let revision: Int64
    let generation: Int64
    let generationPublicKey: String
    let devices: [GroupDevice]
    let packages: [KeyPackage]
    let pending: [PendingDevice]
    let transitions: [GenerationTransition]

    enum CodingKeys: String, CodingKey {
        case groupID = "groupId"
        case revision, generation, generationPublicKey, devices, packages, pending, transitions
    }
}

struct GroupSessionResult: Decodable, Equatable {
    let sessionID: String
    let creatorPublicKey: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case sessionID = "sessionId"
        case creatorPublicKey, expiresAt
    }
}

struct GroupTransitionBody: Encodable {
    let expectedRevision: Int64
    let nextGenerationPublicKey: String
    let packages: [KeyPackage]
    let groupSignature: String
    let deviceSignature: String
}

struct EventsResult: Equatable {
    let events: [EventEnvelope]
    let expiresAt: Int64
}

struct APIClient {
    private let baseURL = URL(string: "https://notify.guru")!
    private let maximumResponseBytes = 2 * 1024 * 1024
    private let session: URLSession

    init(session: URLSession = .shared) {
        self.session = session
    }

    func join(_ pairing: PairingLink, identity: DeviceIdentity) async throws -> Int64 {
        guard let group = identity.group else { throw ProtocolError.invalidPairingLink("device group is not ready") }
        let proof = try CryptoEngine.pairingProof(
            authSecret: pairing.authSecret,
            sessionID: pairing.sessionID,
            pairingID: pairing.pairingID,
            groupID: group.groupID,
            revision: group.revision,
            generation: group.generation,
            groupPublicKey: group.publicKey
        )
        let body = JoinRequest(
            pairingID: pairing.pairingID,
            pairingToken: pairing.pairingToken,
            groupID: group.groupID,
            deviceID: identity.deviceID,
            deviceAccessToken: identity.accessToken,
            revision: group.revision,
            generation: group.generation,
            groupPublicKey: group.publicKey,
            proof: proof
        )
        let data = try await request(
            method: "POST",
            path: "/api/sessions/\(pairing.sessionID)/v2/join",
            token: nil,
            body: try JSONEncoder().encode(body),
            expectedStatus: 201
        )
        let fields = try object(data, keys: ["joined", "expiresAt"])
        guard fields["joined"] as? Bool == true else {
            throw ProtocolError.invalidResponse("join was not confirmed")
        }
        return try integer(fields, "expiresAt")
    }

    func events(for record: SessionRecord, identity: DeviceIdentity) async throws -> EventsResult {
        var components = URLComponents()
        components.path = record.protocolVersion == 2
            ? "/api/sessions/\(record.sessionID)/v2/events"
            : "/api/sessions/\(record.sessionID)/events"
        components.queryItems = [URLQueryItem(name: "groupId", value: record.groupID)]
        if record.protocolVersion == 2 {
            components.queryItems?.append(URLQueryItem(name: "deviceId", value: identity.deviceID))
        }
        components.queryItems?.append(URLQueryItem(name: "after", value: String(record.cursor)))
        guard let path = components.string else {
            throw ProtocolError.invalidResponse("could not construct events URL")
        }
        let data = try await request(
            method: "GET",
            path: path,
            token: record.protocolVersion == 2 ? identity.accessToken : record.groupAccessToken,
            body: nil,
            expectedStatus: 200
        )
        let fields = try object(data, keys: ["events", "expiresAt"])
        guard let eventObjects = fields["events"] as? [[String: Any]] else {
            throw ProtocolError.invalidResponse("events must be an array of objects")
        }
        let events = try eventObjects.map { event -> EventEnvelope in
            let expected = record.protocolVersion == 2
                ? Set(["sequence", "eventId", "groupId", "generation", "nonce", "ciphertext", "createdAt"])
                : Set(["sequence", "eventId", "groupId", "nonce", "ciphertext", "createdAt"])
            try requireKeys(event, expected)
            let envelope = EventEnvelope(
                sequence: try integer(event, "sequence"),
                eventID: try text(event, "eventId"),
                groupID: try text(event, "groupId"),
                generation: record.protocolVersion == 2 ? try integer(event, "generation") : nil,
                nonce: try text(event, "nonce"),
                ciphertext: try text(event, "ciphertext"),
                createdAt: try integer(event, "createdAt")
            )
            guard envelope.groupID == record.groupID else {
                throw ProtocolError.invalidResponse("event group does not match the requested group")
            }
            return envelope
        }
        return EventsResult(events: events, expiresAt: try integer(fields, "expiresAt"))
    }

    func postResponse(
        session record: SessionRecord,
        identity: DeviceIdentity,
        generation: Int64?,
        responseID: String,
        payload: EncryptedPayload
    ) async throws -> Int64 {
        let body = PostResponseRequest(
            responseID: responseID,
            groupID: record.groupID,
            deviceID: record.protocolVersion == 2 ? identity.deviceID : nil,
            generation: generation,
            nonce: payload.nonce,
            ciphertext: payload.ciphertext
        )
        let data = try await request(
            method: "POST",
            path: record.protocolVersion == 2
                ? "/api/sessions/\(record.sessionID)/v2/responses"
                : "/api/sessions/\(record.sessionID)/responses",
            token: record.protocolVersion == 2 ? identity.accessToken : record.groupAccessToken,
            body: try JSONEncoder().encode(body),
            expectedStatus: 201
        )
        let fields = try object(data, keys: ["expiresAt"])
        return try integer(fields, "expiresAt")
    }

    func registerPushToken(
        _ deviceToken: String,
        environment: PushEnvironment,
        session record: SessionRecord,
        identity: DeviceIdentity
    ) async throws -> Int64 {
        let body = RegisterPushRequest(
            groupID: record.groupID,
            deviceID: record.protocolVersion == 2 ? identity.deviceID : nil,
            deviceToken: deviceToken,
            environment: environment
        )
        let data = try await request(
            method: "PUT",
            path: record.protocolVersion == 2
                ? "/api/sessions/\(record.sessionID)/v2/push"
                : "/api/sessions/\(record.sessionID)/push",
            token: record.protocolVersion == 2 ? identity.accessToken : record.groupAccessToken,
            body: try JSONEncoder().encode(body),
            expectedStatus: 200
        )
        let fields = try object(data, keys: ["registered", "expiresAt"])
        guard fields["registered"] as? Bool == true else {
            throw ProtocolError.invalidResponse("push token registration was not confirmed")
        }
        return try integer(fields, "expiresAt")
    }

    func createGroup(
        groupID: String,
        identity: DeviceIdentity,
        generation: GenerationKey,
        package: KeyPackage,
        deviceSignature: String
    ) async throws {
        let body = CreateGroupRequest(
            groupID: groupID,
            deviceID: identity.deviceID,
            deviceAccessTokenHash: CryptoEngine.hashToken(identity.accessToken),
            deviceEncryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity),
            deviceSigningPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            generationPublicKey: generation.publicKey,
            package: package,
            deviceSignature: deviceSignature
        )
        let data = try await request(method: "POST", path: "/api/groups", token: nil, body: try JSONEncoder().encode(body), expectedStatus: 201)
        let fields = try object(data, keys: ["created", "revision", "generation"])
        guard fields["created"] as? Bool == true,
              try integer(fields, "revision") == 1,
              try integer(fields, "generation") == 1 else {
            throw ProtocolError.invalidResponse("group creation was not confirmed")
        }
    }

    func groupState(identity: DeviceIdentity, afterGeneration: Int64) async throws -> DeviceGroupStateResult {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        var components = URLComponents()
        components.path = "/api/groups/\(group.groupID)/state"
        components.queryItems = [
            URLQueryItem(name: "deviceId", value: identity.deviceID),
            URLQueryItem(name: "afterGeneration", value: String(afterGeneration)),
        ]
        let data = try await request(method: "GET", path: components.string!, token: identity.accessToken, body: nil, expectedStatus: 200)
        _ = try object(data, keys: ["groupId", "revision", "generation", "generationPublicKey", "devices", "packages", "pending", "transitions"])
        let result = try JSONDecoder().decode(DeviceGroupStateResult.self, from: data)
        guard result.groupID == group.groupID else { throw ProtocolError.invalidResponse("group state ID mismatch") }
        return result
    }

    func createInvitation(identity: DeviceIdentity, invitationID: String, tokenHash: String) async throws -> Int64 {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        var components = URLComponents()
        components.path = "/api/groups/\(group.groupID)/invitations"
        components.queryItems = [URLQueryItem(name: "deviceId", value: identity.deviceID)]
        let body = InvitationRequest(invitationID: invitationID, invitationTokenHash: tokenHash)
        let data = try await request(method: "POST", path: components.string!, token: identity.accessToken, body: try JSONEncoder().encode(body), expectedStatus: 201)
        let fields = try object(data, keys: ["created", "expiresAt"])
        guard fields["created"] as? Bool == true else { throw ProtocolError.invalidResponse("invitation was not created") }
        return try integer(fields, "expiresAt")
    }

    func submitJoinRequest(_ invitation: DeviceInvitationLink, identity: DeviceIdentity) async throws -> Int64 {
        let body = SubmitJoinRequest(
            invitationID: invitation.invitationID,
            invitationToken: invitation.invitationToken,
            deviceID: identity.deviceID,
            deviceAccessTokenHash: CryptoEngine.hashToken(identity.accessToken),
            deviceEncryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity),
            deviceSigningPublicKey: try CryptoEngine.signingPublicKey(for: identity)
        )
        let data = try await request(
            method: "POST", path: "/api/groups/\(invitation.groupID)/join-requests", token: nil,
            body: try JSONEncoder().encode(body), expectedStatus: 201
        )
        let fields = try object(data, keys: ["requested", "expiresAt"])
        guard fields["requested"] as? Bool == true else { throw ProtocolError.invalidResponse("join request was not submitted") }
        return try integer(fields, "expiresAt")
    }

    func joinRequestStatus(_ invitation: DeviceInvitationRecord) async throws -> String {
        let data = try await request(
            method: "GET",
            path: "/api/groups/\(invitation.groupID)/join-requests/\(invitation.invitationID)",
            token: invitation.invitationToken,
            body: nil,
            expectedStatus: 200
        )
        let fields = try object(data, keys: ["status"])
        return try text(fields, "status")
    }

    func approveJoin(identity: DeviceIdentity, invitationID: String, body: GroupTransitionBody) async throws {
        try await groupTransition(
            identity: identity,
            path: "/join-requests/\(invitationID)/approve",
            body: body,
            confirmation: "approved"
        )
    }

    func rejectJoin(identity: DeviceIdentity, invitationID: String) async throws {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        var components = URLComponents()
        components.path = "/api/groups/\(group.groupID)/join-requests/\(invitationID)/reject"
        components.queryItems = [URLQueryItem(name: "deviceId", value: identity.deviceID)]
        let data = try await request(method: "POST", path: components.string!, token: identity.accessToken, body: nil, expectedStatus: 200)
        let fields = try object(data, keys: ["rejected", "revision"])
        guard fields["rejected"] as? Bool == true else { throw ProtocolError.invalidResponse("join rejection was not confirmed") }
    }

    func removeDevice(identity: DeviceIdentity, deviceID: String, body: GroupTransitionBody) async throws {
        try await groupTransition(identity: identity, path: "/devices/\(deviceID)/remove", body: body, confirmation: "removed")
    }

    func groupSessions(identity: DeviceIdentity) async throws -> [GroupSessionResult] {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        var components = URLComponents()
        components.path = "/api/groups/\(group.groupID)/sessions"
        components.queryItems = [URLQueryItem(name: "deviceId", value: identity.deviceID)]
        let data = try await request(method: "GET", path: components.string!, token: identity.accessToken, body: nil, expectedStatus: 200)
        _ = try object(data, keys: ["sessions"])
        return try JSONDecoder().decode(GroupSessionsEnvelope.self, from: data).sessions
    }

    private func groupTransition(
        identity: DeviceIdentity,
        path: String,
        body: GroupTransitionBody,
        confirmation: String
    ) async throws {
        guard let group = identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        var components = URLComponents()
        components.path = "/api/groups/\(group.groupID)\(path)"
        components.queryItems = [URLQueryItem(name: "deviceId", value: identity.deviceID)]
        let data = try await request(method: "POST", path: components.string!, token: identity.accessToken, body: try JSONEncoder().encode(body), expectedStatus: 200)
        let fields = try object(data, keys: [confirmation, "revision", "generation"])
        guard fields[confirmation] as? Bool == true else { throw ProtocolError.invalidResponse("group transition was not confirmed") }
    }

    private func request(
        method: String,
        path: String,
        token: String?,
        body: Data?,
        expectedStatus: Int
    ) async throws -> Data {
        guard let url = URL(string: path, relativeTo: baseURL)?.absoluteURL,
              url.scheme == "https",
              url.host == baseURL.host else {
            throw ProtocolError.invalidResponse("invalid API URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = 20
        request.httpBody = body
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if body != nil {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw ProtocolError.invalidResponse("API did not return HTTP")
        }
        guard data.count <= maximumResponseBytes else {
            throw ProtocolError.invalidResponse("body exceeds \(maximumResponseBytes) bytes")
        }
        guard http.statusCode == expectedStatus else {
            throw try apiError(status: http.statusCode, data: data)
        }
        return data
    }

    private func apiError(status: Int, data: Data) throws -> APIError {
        let fields = try object(data, keys: ["error", "message"])
        return APIError(
            status: status,
            code: try text(fields, "error"),
            message: try text(fields, "message")
        )
    }

    private func object(_ data: Data, keys: Set<String>) throws -> [String: Any] {
        let value = try JSONSerialization.jsonObject(with: data)
        guard let fields = value as? [String: Any] else {
            throw ProtocolError.invalidResponse("body must be an object")
        }
        try requireKeys(fields, keys)
        return fields
    }

    private func requireKeys(_ fields: [String: Any], _ expected: Set<String>) throws {
        guard Set(fields.keys) == expected else {
            throw ProtocolError.invalidResponse("object fields do not match the protocol")
        }
    }

    private func text(_ fields: [String: Any], _ name: String) throws -> String {
        guard let value = fields[name] as? String, !value.isEmpty else {
            throw ProtocolError.invalidResponse("\(name) must be a non-empty string")
        }
        return value
    }

    private func integer(_ fields: [String: Any], _ name: String) throws -> Int64 {
        guard let number = fields[name] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw ProtocolError.invalidResponse("\(name) must be an integer")
        }
        let value = number.int64Value
        guard value >= 0, NSNumber(value: value) == number else {
            throw ProtocolError.invalidResponse("\(name) must be a non-negative integer")
        }
        return value
    }
}

struct APIError: LocalizedError, Equatable {
    let status: Int
    let code: String
    let message: String

    var errorDescription: String? {
        "notify.guru API: \(code) (\(status)): \(message)"
    }
}

private struct JoinRequest: Encodable {
    let pairingID: String
    let pairingToken: String
    let groupID: String
    let deviceID: String
    let deviceAccessToken: String
    let revision: Int64
    let generation: Int64
    let groupPublicKey: String
    let proof: String

    enum CodingKeys: String, CodingKey {
        case pairingID = "pairingId"
        case pairingToken
        case groupID = "groupId"
        case deviceID = "deviceId"
        case deviceAccessToken
        case revision
        case generation
        case groupPublicKey
        case proof
    }
}

private struct CreateGroupRequest: Encodable {
    let groupID: String
    let deviceID: String
    let deviceAccessTokenHash: String
    let deviceEncryptionPublicKey: String
    let deviceSigningPublicKey: String
    let generationPublicKey: String
    let package: KeyPackage
    let deviceSignature: String

    enum CodingKeys: String, CodingKey {
        case groupID = "groupId"
        case deviceID = "deviceId"
        case deviceAccessTokenHash, deviceEncryptionPublicKey, deviceSigningPublicKey
        case generationPublicKey, package, deviceSignature
    }
}

private struct InvitationRequest: Encodable {
    let invitationID: String
    let invitationTokenHash: String

    enum CodingKeys: String, CodingKey {
        case invitationID = "invitationId"
        case invitationTokenHash
    }
}

private struct SubmitJoinRequest: Encodable {
    let invitationID: String
    let invitationToken: String
    let deviceID: String
    let deviceAccessTokenHash: String
    let deviceEncryptionPublicKey: String
    let deviceSigningPublicKey: String

    enum CodingKeys: String, CodingKey {
        case invitationID = "invitationId"
        case invitationToken
        case deviceID = "deviceId"
        case deviceAccessTokenHash, deviceEncryptionPublicKey, deviceSigningPublicKey
    }
}

private struct GroupSessionsEnvelope: Decodable {
    let sessions: [GroupSessionResult]
}

private struct PostResponseRequest: Encodable {
    let responseID: String
    let groupID: String
    let deviceID: String?
    let generation: Int64?
    let nonce: String
    let ciphertext: String

    enum CodingKeys: String, CodingKey {
        case responseID = "responseId"
        case groupID = "groupId"
        case deviceID = "deviceId"
        case generation
        case nonce
        case ciphertext
    }
}

private struct RegisterPushRequest: Encodable {
    let groupID: String
    let deviceID: String?
    let deviceToken: String
    let environment: PushEnvironment

    enum CodingKeys: String, CodingKey {
        case groupID = "groupId"
        case deviceID = "deviceId"
        case deviceToken
        case environment
    }
}
