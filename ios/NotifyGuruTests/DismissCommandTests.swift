import CryptoKit
import Foundation
import XCTest
@testable import NotifyGuru

final class DismissCommandTests: XCTestCase {
    @MainActor
    func testDismissWaitsForSyncAndSendsOriginalIDAfterReplacement() async throws {
        try await checkQueuedDismiss(syncFails: false)
    }

    @MainActor
    func testQueuedDismissRunsAfterSyncFailure() async throws {
        try await checkQueuedDismiss(syncFails: true)
    }

    @MainActor
    private func checkQueuedDismiss(syncFails: Bool) async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        var initialVault = fixture.vault
        initialVault.sessions[0].request = request("A")
        let model = AppModel(
            commandExecutor: executor,
            initialState: AppCommandState(
                vault: initialVault, groupState: fixture.state,
                pendingDeviceRequest: nil
            )
        )
        let syncing = expectation(description: "sync waiting for server")
        let submitted = expectation(description: "dismiss submitted while sync is running")
        let posted = expectation(description: "dismiss A sent")
        let releaseSync = DispatchSemaphore(value: 0)
        defer { releaseSync.signal() }
        let baseResponse = AppCommandTestTransport.response!
        let response = try requestEvent(fixture: fixture, id: "B")
        AppCommandTestTransport.response = { request in
            if request.url!.path.hasSuffix("/events") {
                syncing.fulfill()
                guard releaseSync.wait(timeout: .now() + 5) == .success else {
                    throw ProtocolError.invalidResponse("test did not release sync")
                }
                if syncFails { throw URLError(.notConnectedToInternet) }
                return response
            }
            if request.httpMethod == "POST" {
                try Self.assertDismiss(request, target: "A", fixture: fixture)
                posted.fulfill()
                return try JSONSerialization.data(withJSONObject: ["expiresAt": fixture.expiresAt])
            }
            return try baseResponse(request)
        }
        let sync = Task { await model.sync() }
        await fulfillment(of: [syncing], timeout: 2)
        let dismiss = Task {
            submitted.fulfill()
            await model.dismissRequest(sessionID: "session", requestID: "A")
        }
        await fulfillment(of: [submitted], timeout: 2)
        XCTAssertNil(model.errorMessage)
        releaseSync.signal()
        await sync.value
        await dismiss.value
        await fulfillment(of: [posted], timeout: 2)
        XCTAssertEqual(model.sessions.first?.request?.id, syncFails ? nil : "B")
        XCTAssertEqual(storage.saved.last?.sessions.first?.request?.id, syncFails ? nil : "B")
        if syncFails { XCTAssertNotNil(model.errorMessage) }
        else { XCTAssertNil(model.errorMessage) }
    }

    @MainActor
    func testRequestDismissSendsTargetAndSavesCompletion() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        var initialVault = fixture.vault
        initialVault.sessions[0].request = request("A")
        AppCommandTestTransport.response = { request in
            try Self.assertDismiss(request, target: "A", fixture: fixture)
            return try JSONSerialization.data(withJSONObject: ["expiresAt": fixture.expiresAt])
        }
        let model = AppModel(
            commandExecutor: executor,
            initialState: AppCommandState(
                vault: initialVault, groupState: fixture.state,
                pendingDeviceRequest: nil
            )
        )
        await model.dismissRequest(sessionID: "session", requestID: "A")
        XCTAssertNil(model.errorMessage)
        XCTAssertNil(model.sessions.first?.request)
        XCTAssertEqual(model.sessions.first?.status, "Request dismissed")
        XCTAssertEqual(storage.saved.last?.sessions.first?.expiresAt, fixture.expiresAt)
    }

    @MainActor
    func testNotificationDismissSendsTargetAndKeepsOtherNotification() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        var initialVault = fixture.vault
        initialVault.sessions[0].notifications = notifications()
        AppCommandTestTransport.response = { request in
            try Self.assertDismiss(request, target: "N1", fixture: fixture)
            return try JSONSerialization.data(withJSONObject: ["expiresAt": fixture.expiresAt])
        }
        let model = AppModel(
            commandExecutor: executor,
            initialState: AppCommandState(
                vault: initialVault, groupState: fixture.state,
                pendingDeviceRequest: nil
            )
        )
        await model.dismissNotification(sessionID: "session", notificationID: "N1")
        XCTAssertNil(model.errorMessage)
        XCTAssertEqual(model.sessions.first?.notifications.map(\.id), ["N2"])
        XCTAssertEqual(storage.saved.last?.sessions.first?.notifications.map(\.id), ["N2"])
    }

    @MainActor
    func testRequestDismissNetworkFailureKeepsTargetVisible() async throws {
        try await checkFailure(notification: false, storageFailure: false)
    }

    @MainActor
    func testRequestDismissStorageFailureKeepsTargetVisible() async throws {
        try await checkFailure(notification: false, storageFailure: true)
    }

    @MainActor
    func testNotificationDismissNetworkFailureKeepsTargetVisible() async throws {
        try await checkFailure(notification: true, storageFailure: false)
    }

    @MainActor
    func testNotificationDismissStorageFailureKeepsTargetVisible() async throws {
        try await checkFailure(notification: true, storageFailure: true)
    }

    @MainActor
    private func checkFailure(notification: Bool, storageFailure: Bool) async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        storage.fail = storageFailure
        let executor = fixture.executor(storage: storage)
        var initialVault = fixture.vault
        initialVault.sessions[0].request = request("A")
        initialVault.sessions[0].notifications = notifications()
        AppCommandTestTransport.response = { request in
            try Self.assertDismiss(request, target: notification ? "N1" : "A", fixture: fixture)
            if !storageFailure { throw URLError(.notConnectedToInternet) }
            return try JSONSerialization.data(withJSONObject: ["expiresAt": fixture.expiresAt])
        }
        let model = AppModel(
            commandExecutor: executor,
            initialState: AppCommandState(
                vault: initialVault, groupState: fixture.state,
                pendingDeviceRequest: nil
            )
        )
        if notification { await model.dismissNotification(sessionID: "session", notificationID: "N1") }
        else { await model.dismissRequest(sessionID: "session", requestID: "A") }
        XCTAssertNotNil(model.errorMessage)
        XCTAssertEqual(model.connectionState, .failed)
        XCTAssertEqual(model.sessions.first?.request?.id, "A")
        XCTAssertEqual(model.sessions.first?.notifications.map(\.id), ["N1", "N2"])
        XCTAssertTrue(storage.saved.isEmpty)
    }

    private func request(_ id: String) -> SessionRequest {
        SessionRequest(id: id, prompt: id, options: [
            SessionChoice(id: "yes", label: "Yes"), SessionChoice(id: "no", label: "No"),
        ], serverItemID: id)
    }

    private func notifications() -> [SessionNotification] {
        ["N1", "N2"].map { SessionNotification(id: $0, message: $0, createdAt: 1, serverItemID: $0) }
    }

    private func requestEvent(fixture: AppCommandFixture, id: String) throws -> Data {
        let session = fixture.vault.sessions[0]
        let key = fixture.vault.identity.group!.keys.values.first!
        let sessionKey = try CryptoEngine.deriveSessionKey(
            key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID,
            groupID: session.groupID, protocolVersion: 4
        )
        let data = try JSONSerialization.data(withJSONObject: [
            "id": "event", "type": "request", "sessionTitle": "Updated", "requestId": id,
            "prompt": "New request", "options": [["id": "yes", "label": "Yes"], ["id": "no", "label": "No"]],
            "color": "#ffffff", "createdAt": "2026-09-10T00:00:00Z",
        ])
        let aad = Data("notify.guru/v4/event/session/group/\(key.timestamp)/event".utf8)
        let sealed = try AES.GCM.seal(data, using: SymmetricKey(data: sessionKey), authenticating: aad)
        return try JSONSerialization.data(withJSONObject: [
            "events": [["sequence": 1, "eventId": "event", "itemId": id, "groupId": "group",
                        "keyTimestamp": key.timestamp, "nonce": Base64URL.encode(Data(sealed.nonce)),
                        "ciphertext": Base64URL.encode(sealed.ciphertext + sealed.tag), "createdAt": 1]],
            "activeItemIds": [id], "attention": false, "expiresAt": fixture.expiresAt,
        ])
    }

    private static func assertDismiss(_ request: URLRequest, target: String, fixture: AppCommandFixture) throws {
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url!.path, "/api/sessions/session/responses")
        let data: Data
        if let body = request.httpBody { data = body }
        else {
            let stream = try XCTUnwrap(request.httpBodyStream)
            stream.open()
            defer { stream.close() }
            var bytes = Data()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while true {
                let count = stream.read(&buffer, maxLength: buffer.count)
                if count == 0 { break }
                if count < 0 { throw try XCTUnwrap(stream.streamError) }
                bytes.append(contentsOf: buffer.prefix(count))
            }
            data = bytes
        }
        let body = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(body["itemId"] as? String, target)
        let responseID = try XCTUnwrap(body["responseId"] as? String)
        let key = fixture.vault.identity.group!.keys.values.first!
        let session = fixture.vault.sessions[0]
        let sessionKey = try CryptoEngine.deriveSessionKey(
            key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID,
            groupID: session.groupID, protocolVersion: 4
        )
        let ciphertext = try Base64URL.decode(XCTUnwrap(body["ciphertext"] as? String))
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Base64URL.decode(XCTUnwrap(body["nonce"] as? String))),
            ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16)
        )
        let aad = Data("notify.guru/v4/response/session/group/\(key.timestamp)/\(responseID)".utf8)
        let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: sessionKey), authenticating: aad)
        let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
        XCTAssertEqual(payload["type"] as? String, "dismiss")
        XCTAssertEqual(payload["eventId"] as? String, target)
        XCTAssertNil(payload["requestId"])
    }
}
