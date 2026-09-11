#if DEBUG
import Foundation

final class CommandUITestStorage: AppCommandStorage {
    private(set) var vault: Vault?
    func save(_ vault: Vault) throws { self.vault = vault }
}

final class CommandUITestTransport: URLProtocol {
    static var relay: CommandUITestRelay!

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let (status, data) = try Self.relay.respond(to: request)
            client!.urlProtocol(self, didReceive: HTTPURLResponse(
                url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil
            )!, cacheStoragePolicy: .notAllowed)
            client!.urlProtocol(self, didLoad: data)
            client!.urlProtocolDidFinishLoading(self)
        } catch {
            client!.urlProtocol(self, didFailWithError: error)
        }
    }
    override func stopLoading() {}
}

final class CommandUITestRelay {
    let vault: Vault
    let otherDevice: DeviceIdentity
    let request: DeviceRequestDescriptor
    let requestURL: String
    let pairingURL: String
    var groups: [String: DeviceGroupStateResult]
    var requests: [(method: String, path: String, body: [String: Any])] = []
    var failPath: String?
    var failure: Error = URLError(.notConnectedToInternet)
    let expiresAt = Int64(Date().timeIntervalSince1970 * 1_000) + 86_400_000

    init() throws {
        var identity = try CryptoEngine.createIdentity()
        identity.deviceID = "ui-test-device"
        var other = try CryptoEngine.createIdentity()
        other.deviceID = "ui-test-other-device"
        otherDevice = other
        let member = TransitionMember(
            deviceID: identity.deviceID, signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
        )
        let draft = CryptoEngine.createGroupKey()
        let package = try CryptoEngine.createKeyPackage(
            groupID: "ui-test-group", key: draft, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let transition = try CryptoEngine.createGroupTransition(
            groupID: "ui-test-group", identity: identity, groupKey: draft, previous: nil,
            members: [member], packages: [package], recreated: true, now: 42
        )
        let key = GroupKey(timestamp: transition.timestamp, publicKey: draft.publicKey,
                           privateKey: draft.privateKey, transitionHash: transition.transitionHash)
        identity.group = DeviceGroup(groupID: "ui-test-group", keys: [String(key.timestamp): key],
                                    rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash)
        vault = Vault(version: 4, identity: identity, sessions: [])
        groups = ["ui-test-group": DeviceGroupStateResult(
            groupID: "ui-test-group", members: [GroupDevice(deviceID: member.deviceID,
                encryptionPublicKey: member.encryptionPublicKey, signingPublicKey: member.signingPublicKey, addedAt: 42)],
            keys: [transition], packages: [], sessions: []
        )]
        request = DeviceRequestDescriptor(
            requestID: "ui-test-device-request", deviceID: other.deviceID,
            accessHash: CryptoEngine.hashToken(other.accessToken),
            signingPublicKey: try CryptoEngine.signingPublicKey(for: other),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: other), protocolVersion: 4
        )
        let hash = CryptoEngine.deviceRequestBindingHash(
            requestID: request.requestID, deviceID: request.deviceID, signingPublicKey: request.signingPublicKey,
            accessHash: request.accessHash, encryptionPublicKey: request.encryptionPublicKey, protocolVersion: 4
        )
        let secret = Base64URL.encode(Data(repeating: 7, count: 32))
        requestURL = "https://notify.guru/device#v=3&r=\(request.requestID)&a=\(secret)&h=\(hash)"
        pairingURL = "https://notify.guru/join#v=4&s=ui-test-joined-session&p=ui-test-pairing-id&t=\(secret)&a=\(secret)&k=\(draft.publicKey)&c=d9f2d0"
    }

    func addSession(_ session: SessionRecord) throws {
        let group = groups[session.groupID]!
        let key = vault.identity.group!.keys.values.first!
        let descriptor = try CryptoEngine.createSessionDescriptor(identity: vault.identity, key: key,
            sessionID: session.sessionID, groupID: session.groupID, creatorPublicKey: session.creatorPublicKey)
        let remote = GroupSessionResult(protocolVersion: 4, sessionID: session.sessionID,
            groupID: session.groupID, creatorPublicKey: session.creatorPublicKey, expiresAt: session.expiresAt,
            keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
            actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
            continuitySignature: descriptor.continuitySignature)
        groups[group.groupID] = DeviceGroupStateResult(groupID: group.groupID, members: group.members,
            keys: group.keys, packages: group.packages, sessions: group.sessions + [remote])
    }

    func respond(to request: URLRequest) throws -> (Int, Data) {
        let path = request.url!.path
        let method = request.httpMethod!
        let body: [String: Any]
        if path.contains("/attachments/") && method == "PUT" { body = [:] }
        else {
            let data = try Self.bodyData(request)
            if data.isEmpty { body = [:] }
            else {
                guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    throw ProtocolError.invalidResponse("test request body is not an object")
                }
                body = object
            }
        }
        requests.append((method, path, body))
        if path == failPath { throw failure }
        func json(_ status: Int, _ object: [String: Any]) throws -> (Int, Data) {
            (status, try JSONSerialization.data(withJSONObject: object))
        }
        if method == "POST", path == "/api/devices" {
            return try json(201, ["deviceId": vault.identity.deviceID])
        }
        if method == "GET", path.hasSuffix("/state") {
            let id = String(path.split(separator: "/")[2])
            guard let group = groups[id] else { throw ProtocolError.invalidResponse("unknown test group") }
            return (200, try JSONEncoder().encode(group))
        }
        if method == "POST", path == "/api/groups" {
            let id = body["groupId"] as! String
            try installTransition(body, groupID: id)
            return try json(201, ["created": true, "groupId": id])
        }
        if method == "GET", path.hasSuffix("/device-requests/\(self.request.requestID)") {
            return (200, try JSONEncoder().encode(self.request))
        }
        if method == "POST", path.hasSuffix("/approve") {
            let id = String(path.split(separator: "/")[2])
            let transition = try installTransition(body, groupID: id)
            return try json(200, ["approved": true, "deviceId": self.request.deviceID,
                                 "approvedByDeviceId": vault.identity.deviceID, "transitionHash": transition.transitionHash])
        }
        if method == "POST", path.hasSuffix("/keys") {
            let transition = try installTransition(body, groupID: String(path.split(separator: "/")[2]))
            return try json(201, ["timestamp": transition.timestamp, "transitionHash": transition.transitionHash])
        }
        if method == "DELETE", path.contains("/devices/") {
            let id = String(path.split(separator: "/")[2])
            if let hash = body["headTransitionHash"] as? String {
                groups.removeValue(forKey: id)
                return try json(200, ["removed": true, "transitionHash": hash])
            }
            let transition = try installTransition(body, groupID: id)
            return try json(200, ["removed": true, "transitionHash": transition.transitionHash])
        }
        if method == "POST", path == "/api/device-requests" {
            let id = body["requestId"] as! String
            let hash = CryptoEngine.deviceRequestBindingHash(
                requestID: id, deviceID: vault.identity.deviceID,
                signingPublicKey: try CryptoEngine.signingPublicKey(for: vault.identity),
                accessHash: body["deviceAccessTokenHash"] as! String,
                encryptionPublicKey: body["deviceEncryptionPublicKey"] as! String, protocolVersion: 4
            )
            return try json(201, ["requestId": id, "requestHash": hash, "expiresAt": expiresAt])
        }
        if method == "GET", path.hasPrefix("/api/device-requests/") {
            return try json(200, ["status": "waiting", "expiresAt": expiresAt])
        }
        if method == "POST", path.hasSuffix("/join") {
            let descriptor = try JSONDecoder().decode(SignedSessionDescriptor.self,
                from: JSONSerialization.data(withJSONObject: body["sessionDescriptor"]!))
            let group = groups[descriptor.groupID]!
            let session = GroupSessionResult(protocolVersion: 4, sessionID: descriptor.sessionID,
                groupID: descriptor.groupID, creatorPublicKey: descriptor.creatorPublicKey, expiresAt: expiresAt,
                keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
                actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
                continuitySignature: descriptor.continuitySignature)
            groups[group.groupID] = DeviceGroupStateResult(groupID: group.groupID, members: group.members,
                keys: group.keys, packages: group.packages, sessions: group.sessions + [session])
            return try json(201, ["joined": true, "expiresAt": expiresAt])
        }
        if method == "GET", path.hasSuffix("/events") {
            return try json(200, ["events": [], "activeItemIds": ["request-1", "notice-1", "notice-2"],
                                  "attention": false, "expiresAt": expiresAt])
        }
        if method == "PUT", path.hasSuffix("/attention") {
            return try json(200, ["attention": body["attention"]!, "expiresAt": expiresAt])
        }
        if method == "PUT", path.hasSuffix("/push") { return try json(200, ["updated": true]) }
        if method == "POST", path.hasSuffix("/attachments") {
            return try json(201, ["attachmentId": body["attachmentId"]!, "uploadToken": "test-upload-token",
                                  "maxCiphertextBytes": 10_000_000, "uploadExpiresAt": expiresAt])
        }
        if method == "PUT", path.contains("/attachments/") { return try json(200, ["uploaded": true]) }
        if method == "POST", path.hasSuffix("/responses") { return try json(201, ["expiresAt": expiresAt]) }
        throw ProtocolError.invalidResponse("unexpected test request: \(method) \(path)")
    }

    @discardableResult
    private func installTransition(_ body: [String: Any], groupID: String) throws -> GroupKeyRecord {
        let transition = try JSONDecoder().decode(GroupKeyRecord.self,
            from: JSONSerialization.data(withJSONObject: body["transition"]!))
        let packages = try JSONDecoder().decode([KeyPackage].self,
            from: JSONSerialization.data(withJSONObject: body["packages"]!))
        let previous = groups[groupID]
        groups[groupID] = DeviceGroupStateResult(groupID: groupID,
            members: transition.members.map { GroupDevice(deviceID: $0.deviceID,
                encryptionPublicKey: $0.encryptionPublicKey, signingPublicKey: $0.signingPublicKey, addedAt: transition.timestamp) },
            keys: (previous?.keys ?? []) + [transition],
            packages: packages.filter { $0.deviceID == vault.identity.deviceID }.map {
                KeyPackage(timestamp: transition.timestamp, deviceID: $0.deviceID,
                           ephemeralPublicKey: $0.ephemeralPublicKey, nonce: $0.nonce, ciphertext: $0.ciphertext)
            }, sessions: previous?.sessions ?? [])
        return transition
    }

    static func bodyData(_ request: URLRequest) throws -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count == 0 { return data }
            if count < 0 { throw stream.streamError! }
            data.append(contentsOf: buffer.prefix(count))
        }
    }
}
#endif
