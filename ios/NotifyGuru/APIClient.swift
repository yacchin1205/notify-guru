import Foundation

struct EventEnvelope: Equatable {
    let sequence: Int64
    let eventID: String
    let groupID: String
    let nonce: String
    let ciphertext: String
    let createdAt: Int64
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

    func join(_ pairing: PairingLink, identity: DeviceIdentity, groupAccessToken: String) async throws -> Int64 {
        let groupPublicKey = try CryptoEngine.publicKey(for: identity)
        let proof = try CryptoEngine.pairingProof(
            authSecret: pairing.authSecret,
            sessionID: pairing.sessionID,
            pairingID: pairing.pairingID,
            groupID: identity.groupID,
            groupPublicKey: groupPublicKey
        )
        let body = JoinRequest(
            pairingID: pairing.pairingID,
            pairingToken: pairing.pairingToken,
            groupID: identity.groupID,
            groupAccessTokenHash: CryptoEngine.hashToken(groupAccessToken),
            groupPublicKey: groupPublicKey,
            proof: proof
        )
        let data = try await request(
            method: "POST",
            path: "/api/sessions/\(pairing.sessionID)/join",
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

    func events(for record: SessionRecord) async throws -> EventsResult {
        var components = URLComponents()
        components.path = "/api/sessions/\(record.sessionID)/events"
        components.queryItems = [
            URLQueryItem(name: "groupId", value: record.groupID),
            URLQueryItem(name: "after", value: String(record.cursor)),
        ]
        guard let path = components.string else {
            throw ProtocolError.invalidResponse("could not construct events URL")
        }
        let data = try await request(
            method: "GET",
            path: path,
            token: record.groupAccessToken,
            body: nil,
            expectedStatus: 200
        )
        let fields = try object(data, keys: ["events", "expiresAt"])
        guard let eventObjects = fields["events"] as? [[String: Any]] else {
            throw ProtocolError.invalidResponse("events must be an array of objects")
        }
        let events = try eventObjects.map { event -> EventEnvelope in
            try requireKeys(event, ["sequence", "eventId", "groupId", "nonce", "ciphertext", "createdAt"])
            let envelope = EventEnvelope(
                sequence: try integer(event, "sequence"),
                eventID: try text(event, "eventId"),
                groupID: try text(event, "groupId"),
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
        responseID: String,
        payload: EncryptedPayload
    ) async throws -> Int64 {
        let body = PostResponseRequest(
            responseID: responseID,
            groupID: record.groupID,
            nonce: payload.nonce,
            ciphertext: payload.ciphertext
        )
        let data = try await request(
            method: "POST",
            path: "/api/sessions/\(record.sessionID)/responses",
            token: record.groupAccessToken,
            body: try JSONEncoder().encode(body),
            expectedStatus: 201
        )
        let fields = try object(data, keys: ["expiresAt"])
        return try integer(fields, "expiresAt")
    }

    func registerPushToken(
        _ deviceToken: String,
        environment: PushEnvironment,
        session record: SessionRecord
    ) async throws -> Int64 {
        let body = RegisterPushRequest(
            groupID: record.groupID,
            deviceToken: deviceToken,
            environment: environment
        )
        let data = try await request(
            method: "PUT",
            path: "/api/sessions/\(record.sessionID)/push",
            token: record.groupAccessToken,
            body: try JSONEncoder().encode(body),
            expectedStatus: 200
        )
        let fields = try object(data, keys: ["registered", "expiresAt"])
        guard fields["registered"] as? Bool == true else {
            throw ProtocolError.invalidResponse("push token registration was not confirmed")
        }
        return try integer(fields, "expiresAt")
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
    let groupAccessTokenHash: String
    let groupPublicKey: String
    let proof: String

    enum CodingKeys: String, CodingKey {
        case pairingID = "pairingId"
        case pairingToken
        case groupID = "groupId"
        case groupAccessTokenHash
        case groupPublicKey
        case proof
    }
}

private struct PostResponseRequest: Encodable {
    let responseID: String
    let groupID: String
    let nonce: String
    let ciphertext: String

    enum CodingKeys: String, CodingKey {
        case responseID = "responseId"
        case groupID = "groupId"
        case nonce
        case ciphertext
    }
}

private struct RegisterPushRequest: Encodable {
    let groupID: String
    let deviceToken: String
    let environment: PushEnvironment

    enum CodingKeys: String, CodingKey {
        case groupID = "groupId"
        case deviceToken
        case environment
    }
}
