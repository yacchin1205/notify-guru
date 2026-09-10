import CryptoKit
import Foundation
@testable import NotifyGuru

final class AppCommandTestStorage: AppCommandStorage {
    enum Failure: Error { case expected }
    var saved: [Vault] = []
    var fail = false

    func save(_ vault: Vault) throws {
        if fail { throw Failure.expected }
        saved.append(vault)
    }
}

@MainActor
final class AppCommandTestDriver {
    let executor: AppCommandExecutor
    var state: AppCommandState

    init(executor: AppCommandExecutor, state: AppCommandState) {
        self.executor = executor
        self.state = state
    }

    @discardableResult
    func execute(_ command: AppCommand) async throws -> AppCommandResult {
        let result = try await executor.execute(command, state: state)
        state = result.nextState
        return result
    }
}

final class AppCommandTestTransport: URLProtocol {
    static var response: ((URLRequest) throws -> Data)!

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        do {
            let data = try Self.response(request)
            client!.urlProtocol(self, didReceive: HTTPURLResponse(
                url: request.url!, statusCode: request.httpMethod == "POST" ? 201 : 200, httpVersion: nil, headerFields: nil
            )!, cacheStoragePolicy: .notAllowed)
            client!.urlProtocol(self, didLoad: data)
            client!.urlProtocolDidFinishLoading(self)
        } catch {
            client!.urlProtocol(self, didFailWithError: error)
        }
    }
    override func stopLoading() {}
}

struct AppCommandFixture {
    let vault: Vault
    let state: DeviceGroupStateResult
    let expiresAt = Int64(Date().timeIntervalSince1970 * 1_000) + 86_400_000

    init(sessionIDs: [String] = ["session"]) throws {
        var identity = try CryptoEngine.createIdentity()
        identity.deviceID = "device"
        let member = TransitionMember(
            deviceID: identity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
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
            timestamp: transition.timestamp, publicKey: draft.publicKey,
            privateKey: draft.privateKey, transitionHash: transition.transitionHash
        )
        identity.group = DeviceGroup(
            groupID: "group", keys: [String(key.timestamp): key],
            rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash
        )
        let creator = try CryptoEngine.encryptionPublicKey(for: CryptoEngine.createIdentity())
        let localExpiry = expiresAt - 1_000
        let sessions = sessionIDs.map { id in
            SessionRecord(
                protocolVersion: 4, sessionID: id, groupID: "group", creatorPublicKey: creator,
                keys: [:], cursor: 0, title: "Session", status: "Connected", notifications: [],
                request: nil, requestKeyTimestamp: nil, color: nil, updatedAt: nil, expiresAt: localExpiry
            )
        }
        vault = Vault(version: 4, identity: identity, sessions: sessions)
        let remoteSessions = try sessions.map { session in
            let descriptor = try CryptoEngine.createSessionDescriptor(
                identity: identity, key: key, sessionID: session.sessionID,
                groupID: "group", creatorPublicKey: creator
            )
            return GroupSessionResult(
                protocolVersion: 4, sessionID: descriptor.sessionID, groupID: "group",
                creatorPublicKey: descriptor.creatorPublicKey, expiresAt: localExpiry,
                keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
                actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
                continuitySignature: descriptor.continuitySignature
            )
        }
        state = DeviceGroupStateResult(
            groupID: "group", members: [GroupDevice(
                deviceID: member.deviceID, encryptionPublicKey: member.encryptionPublicKey,
                signingPublicKey: member.signingPublicKey, addedAt: 10
            )], keys: [transition], packages: [KeyPackage(
                timestamp: transition.timestamp, deviceID: package.deviceID,
                ephemeralPublicKey: package.ephemeralPublicKey, nonce: package.nonce,
                ciphertext: package.ciphertext
            )], sessions: remoteSessions
        )
    }

    @MainActor
    func executor(
        storage: AppCommandTestStorage, badSession: String? = nil,
        invalidGroup: Bool = false, networkFailure: Bool = false,
        pending: DeviceRequestRecord? = nil, invalidApproval: Bool = false
    ) -> AppCommandExecutor {
        AppCommandTestTransport.response = { request in
            if networkFailure { throw URLError(.notConnectedToInternet) }
            let path = request.url!.path
            if let pending, path == "/api/device-requests/\(pending.requestID)" {
                let hash = state.keys.last!.transitionHash
                let proof = try CryptoEngine.deviceApprovalProof(
                    authSecret: pending.authSecret, requestID: pending.requestID,
                    groupID: invalidApproval ? "wrong-group" : "group", transitionHash: hash
                )
                return try JSONSerialization.data(withJSONObject: [
                    "status": "approved", "groupId": "group", "expiresAt": expiresAt,
                    "transitionHash": hash, "approvalProof": proof,
                ])
            }
            if path == "/api/groups/group/state" {
                let result = invalidGroup ? DeviceGroupStateResult(
                    groupID: state.groupID, members: [], keys: state.keys, packages: [], sessions: []
                ) : state
                return try JSONEncoder().encode(result)
            }
            guard let session = vault.sessions.first(where: { path == "/api/sessions/\($0.sessionID)/events" }) else {
                throw ProtocolError.invalidResponse("unexpected request in synchronization test")
            }
            if session.sessionID == badSession { return Data("{}".utf8) }
            let key = vault.identity.group!.keys.values.first!
            let sessionKey = try CryptoEngine.deriveSessionKey(
                key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID,
                groupID: session.groupID, protocolVersion: session.protocolVersion
            )
            let payload = try JSONSerialization.data(withJSONObject: [
                "id": "event", "type": "status", "sessionTitle": "Synchronized",
                "status": "Updated by sync", "color": "#ffffff", "createdAt": "2026-09-10T00:00:00Z",
            ])
            let aad = Data("notify.guru/v4/event/\(session.sessionID)/group/\(key.timestamp)/event".utf8)
            let sealed = try AES.GCM.seal(payload, using: SymmetricKey(data: sessionKey), authenticating: aad)
            return try JSONSerialization.data(withJSONObject: [
                "events": [[
                    "sequence": 1, "eventId": "event", "itemId": NSNull(), "groupId": "group",
                    "keyTimestamp": key.timestamp, "nonce": Base64URL.encode(Data(sealed.nonce)),
                    "ciphertext": Base64URL.encode(sealed.ciphertext + sealed.tag), "createdAt": 1,
                ]],
                "activeItemIds": [], "attention": true, "expiresAt": expiresAt,
            ])
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AppCommandTestTransport.self]
        return AppCommandExecutor(
            api: APIClient(session: URLSession(configuration: configuration)), storage: storage
        )
    }

    func commandState(pendingDeviceRequest: DeviceRequestRecord? = nil) -> AppCommandState {
        var initialVault = vault
        let groupState: DeviceGroupStateResult?
        if pendingDeviceRequest == nil {
            groupState = state
        } else {
            initialVault.identity.group = nil
            initialVault.sessions = []
            groupState = nil
        }
        return AppCommandState(
            vault: initialVault,
            groupState: groupState,
            pendingDeviceRequest: pendingDeviceRequest
        )
    }
}
