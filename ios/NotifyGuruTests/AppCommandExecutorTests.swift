import CryptoKit
import Foundation
import XCTest
@testable import NotifyGuru

final class AppCommandExecutorTests: XCTestCase {
    @MainActor
    func testModelSyncPublishesSavedState() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        let model = AppModel(commandExecutor: executor, initialState: fixture.commandState())
        await model.sync()
        XCTAssertEqual(model.connectionState, .current)
        XCTAssertEqual(model.sessions.first?.status, "Updated by sync")
        XCTAssertEqual(model.sessions, storage.saved.last?.sessions)
        XCTAssertEqual(model.groupDevices, fixture.state.members)
        XCTAssertNil(model.errorMessage)
    }

    @MainActor
    func testModelSyncKeepsFailureVisibleAfterLaterSuccess() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, networkFailure: true)
        let model = AppModel(commandExecutor: executor, initialState: fixture.commandState())
        await model.sync()
        XCTAssertEqual(model.connectionState, .failed)
        let failure = try XCTUnwrap(model.errorMessage)
        _ = fixture.executor(storage: storage)
        await model.sync()
        XCTAssertEqual(model.connectionState, .current)
        XCTAssertEqual(model.sessions.first?.status, "Updated by sync")
        XCTAssertEqual(model.errorMessage, failure)
    }

    @MainActor
    func testModelSyncPublishesSessionFailure() async throws {
        let fixture = try AppCommandFixture(sessionIDs: ["bad", "good"])
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, badSession: "bad")
        let model = AppModel(commandExecutor: executor, initialState: fixture.commandState())
        await model.sync()
        XCTAssertEqual(model.connectionState, .failed)
        XCTAssertEqual(model.sessions.first { $0.sessionID == "good" }?.status, "Connected")
        XCTAssertNotNil(model.sessionSyncErrors["bad"])
        XCTAssertNotNil(model.errorMessage)
    }

    @MainActor
    func testSynchronizeReportsApprovedDeviceAsData() async throws {
        let fixture = try AppCommandFixture()
        let pending = DeviceRequestRecord(
            requestID: "request", expiresAt: fixture.expiresAt,
            authSecret: Base64URL.encode(Data(repeating: 7, count: 32))
        )
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, pending: pending)
        let driver = AppCommandTestDriver(
            executor: executor, state: fixture.commandState(pendingDeviceRequest: pending)
        )
        let result = try await driver.execute(.synchronize)
        XCTAssertEqual(result.changes, [.deviceAdded])
        XCTAssertNil(driver.state.pendingDeviceRequest)
        XCTAssertEqual(driver.state.vault.identity.group?.groupID, "group")
        XCTAssertEqual(driver.state.vault.sessions.first?.status, "Updated by sync")
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testSynchronizeRejectsInvalidApprovalProof() async throws {
        let fixture = try AppCommandFixture()
        let pending = DeviceRequestRecord(
            requestID: "request", expiresAt: fixture.expiresAt,
            authSecret: Base64URL.encode(Data(repeating: 7, count: 32))
        )
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, pending: pending, invalidApproval: true)
        let driver = AppCommandTestDriver(
            executor: executor, state: fixture.commandState(pendingDeviceRequest: pending)
        )
        do {
            try await driver.execute(.synchronize)
            XCTFail("An invalid approval must reach the caller")
        } catch let error as ProtocolError {
            XCTAssertTrue(error.localizedDescription.contains("approval proof"))
        }
        XCTAssertTrue(storage.saved.isEmpty)
        XCTAssertEqual(driver.state.pendingDeviceRequest, pending)
        XCTAssertNil(driver.state.vault.identity.group)
    }


    @MainActor
    func testSynchronizeStoresEventsBeforeReturning() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        let driver = AppCommandTestDriver(executor: executor, state: fixture.commandState())
        let result = try await driver.execute(.synchronize)
        let saved = try XCTUnwrap(storage.saved.last)
        XCTAssertEqual(saved, driver.state.vault)
        XCTAssertEqual(saved.sessions.count, 1)
        XCTAssertEqual(saved.sessions[0].status, "Updated by sync")
        XCTAssertEqual(saved.sessions[0].cursor, 1)
        XCTAssertTrue(saved.sessions[0].attention)
        XCTAssertEqual(saved.sessions[0].expiresAt, fixture.expiresAt)
        XCTAssertTrue(result.changes.isEmpty)
    }

    @MainActor
    func testSynchronizeThrowsSessionErrorImmediately() async throws {
        let fixture = try AppCommandFixture(sessionIDs: ["bad", "good"])
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, badSession: "bad")
        let driver = AppCommandTestDriver(executor: executor, state: fixture.commandState())
        do {
            try await driver.execute(.synchronize)
            XCTFail("Invalid event responses must reach the caller")
        } catch let error as SessionSynchronizationError {
            XCTAssertEqual(error.sessionID, "bad")
        }
        let saved = try XCTUnwrap(storage.saved.last)
        XCTAssertEqual(saved.sessions.first { $0.sessionID == "bad" }?.cursor, 0)
        XCTAssertEqual(saved.sessions.first { $0.sessionID == "good" }?.status, "Connected")
    }

    @MainActor
    func testSynchronizePropagatesStorageFailure() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        storage.fail = true
        let executor = fixture.executor(storage: storage)
        let driver = AppCommandTestDriver(executor: executor, state: fixture.commandState())
        do {
            try await driver.execute(.synchronize)
            XCTFail("A save failure must reach the caller")
        } catch AppCommandTestStorage.Failure.expected { }
        XCTAssertTrue(storage.saved.isEmpty)
        XCTAssertEqual(driver.state.vault, fixture.vault)
    }

    @MainActor
    func testSynchronizeRejectsUnauthenticatedGroup() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, invalidGroup: true)
        let driver = AppCommandTestDriver(executor: executor, state: fixture.commandState())
        do {
            try await driver.execute(.synchronize)
            XCTFail("An untrusted group must not be saved")
        } catch let error as ProtocolError {
            XCTAssertTrue(error.localizedDescription.contains("member"))
        }
        XCTAssertTrue(storage.saved.isEmpty)
        XCTAssertEqual(driver.state.vault, fixture.vault)
    }

    @MainActor
    func testSynchronizePropagatesNetworkFailure() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage, networkFailure: true)
        let driver = AppCommandTestDriver(executor: executor, state: fixture.commandState())
        do {
            try await driver.execute(.synchronize)
            XCTFail("A network failure must reach the caller")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .notConnectedToInternet)
        }
        XCTAssertTrue(storage.saved.isEmpty)
    }
    @MainActor
    func testJoinStoresSpecifiedSessionAndAuthenticatedKeys() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        let session = try XCTUnwrap(driver.state.vault.sessions.first)
        XCTAssertEqual(session.sessionID, "ui-test-joined-session")
        XCTAssertFalse(session.keys.isEmpty)
        XCTAssertEqual(session.expiresAt, relay.expiresAt)
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testApproveAddsAuthenticatedDeviceToSpecifiedGroup() async throws {
        let (relay, driver, storage) = try commandFixture()
        let result = try await driver.execute(
            .approveDeviceAddition(groupID: "ui-test-group", requestURL: relay.requestURL)
        )
        XCTAssertEqual(Set(try XCTUnwrap(result.nextState.groupState).members.map(\.deviceID)), ["ui-test-device", "ui-test-other-device"])
        let approval = try XCTUnwrap(relay.requests.first { $0.path.hasSuffix("/approve") })
        let link = try DeviceRequestLink(relay.requestURL)
        let transition = try JSONDecoder().decode(GroupKeyRecord.self,
            from: JSONSerialization.data(withJSONObject: approval.body["transition"]!))
        XCTAssertTrue(try CryptoEngine.verifyDeviceApprovalProof(authSecret: link.authSecret,
            requestID: link.requestID, groupID: "ui-test-group", transitionHash: transition.transitionHash,
            proof: approval.body["approvalProof"] as! String))
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testRemoveDeviceUpdatesMembershipAndSavesNewKey() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .approveDeviceAddition(groupID: "ui-test-group", requestURL: relay.requestURL)
        )
        let previous = try XCTUnwrap(driver.state.vault.identity.group).headTransitionHash
        let result = try await driver.execute(
            .removeDevice(groupID: "ui-test-group", deviceID: "ui-test-other-device")
        )
        XCTAssertEqual(try XCTUnwrap(result.nextState.groupState).members.map(\.deviceID), ["ui-test-device"])
        XCTAssertNotEqual(driver.state.vault.identity.group?.headTransitionHash, previous)
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testLeaveGroupCreatesSoloGroupAndRemovesItsSessions() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        try await driver.execute(
            .approveDeviceAddition(groupID: "ui-test-group", requestURL: relay.requestURL)
        )
        try await driver.execute(.leaveDeviceGroup(groupID: "ui-test-group"))
        XCTAssertNotEqual(driver.state.vault.identity.group?.groupID, "ui-test-group")
        XCTAssertEqual(try XCTUnwrap(driver.state.groupState).members.map(\.deviceID), ["ui-test-device"])
        XCTAssertTrue(driver.state.vault.sessions.isEmpty)
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testPrepareGroupJoinRequiresConsentToDiscardSessions() async throws {
        let (relay, driver, _) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        do {
            try await driver.execute(
                .prepareDeviceGroupJoin(groupID: "ui-test-group", discardSavedSessions: false)
            )
            XCTFail("Saved sessions require explicit discard consent")
        } catch let error as ProtocolError {
            XCTAssertTrue(error.localizedDescription.contains("confirm removing"))
        }
        XCTAssertFalse(relay.requests.contains { $0.method == "DELETE" })
        XCTAssertEqual(driver.state.vault.sessions.count, 1)
    }

    @MainActor
    func testPrepareGroupJoinAbandonsSoloGroupAndCreatesBoundRequest() async throws {
        let (relay, driver, storage) = try commandFixture()
        let result = try await driver.execute(
            .prepareDeviceGroupJoin(groupID: "ui-test-group", discardSavedSessions: false)
        )
        XCTAssertNil(driver.state.vault.identity.group)
        XCTAssertNil(result.nextState.groupState)
        XCTAssertTrue(result.changes.isEmpty)
        let request = try XCTUnwrap(driver.state.pendingDeviceRequest)
        XCTAssertFalse(request.authSecret.isEmpty)
        XCTAssertFalse(request.requestHash.isEmpty)
        XCTAssertTrue(relay.requests.contains { $0.method == "DELETE" && $0.body["headTransitionHash"] != nil })
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testPrepareGroupJoinLeavesSharedGroupWithConsent() async throws {
        let (relay, driver, _) = try commandFixture()
        try await driver.execute(
            .approveDeviceAddition(groupID: "ui-test-group", requestURL: relay.requestURL)
        )
        try await driver.execute(
            .prepareDeviceGroupJoin(groupID: "ui-test-group", discardSavedSessions: true)
        )
        XCTAssertNil(driver.state.vault.identity.group)
        XCTAssertEqual(relay.groups["ui-test-group"]!.members.map(\.deviceID), ["ui-test-other-device"])
        XCTAssertNotNil(driver.state.pendingDeviceRequest)
    }

    @MainActor
    func testGroupCommandsNeverRetargetAnotherGroup() async throws {
        let (relay, driver, _) = try commandFixture()
        let commands: [AppCommand] = [
            .joinSession(groupID: "other-group", pairingURL: relay.pairingURL),
            .approveDeviceAddition(groupID: "other-group", requestURL: relay.requestURL),
            .prepareDeviceGroupJoin(groupID: "other-group", discardSavedSessions: true),
            .removeDevice(groupID: "other-group", deviceID: "ui-test-other-device"),
            .leaveDeviceGroup(groupID: "other-group"),
        ]
        for command in commands {
            do {
                try await driver.execute(command)
                XCTFail("The specified group must be respected")
            }
            catch let error as ProtocolError { XCTAssertTrue(error.localizedDescription.contains("command's device group")) }
        }
        XCTAssertTrue(relay.requests.isEmpty)
    }

    @MainActor
    func testResponseSendsOriginalRequestAndKeepsReplacement() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        var stateWithReplacement = driver.state
        var vaultWithReplacement = stateWithReplacement.vault
        vaultWithReplacement.sessions[0].request = SessionRequest(id: "B", prompt: "B", options: [])
        stateWithReplacement = AppCommandState(
            vault: vaultWithReplacement,
            groupState: stateWithReplacement.groupState,
            pendingDeviceRequest: stateWithReplacement.pendingDeviceRequest
        )
        driver.state = stateWithReplacement
        try await driver.execute(
            .respond(sessionID: "ui-test-joined-session", requestID: "A", optionID: "yes")
        )
        let sent = try XCTUnwrap(relay.requests.last)
        XCTAssertEqual(sent.body["itemId"] as? String, "A")
        let payload = try decryptResponse(sent.body, vault: driver.state.vault)
        XCTAssertEqual(payload["requestId"] as? String, "A")
        XCTAssertEqual(payload["optionId"] as? String, "yes")
        XCTAssertEqual(driver.state.vault.sessions[0].request?.id, "B")
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testAttentionSavesRequestedValueBeforeReturning() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        try await driver.execute(
            .setAttention(sessionID: "ui-test-joined-session", enabled: true)
        )
        XCTAssertEqual(relay.requests.last!.body["attention"] as? Bool, true)
        XCTAssertTrue(driver.state.vault.sessions[0].attention)
        XCTAssertEqual(storage.saved.last, driver.state.vault)
    }

    @MainActor
    func testFeedbackPreservesPhotoOrderAndDoesNotSaveExpiry() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        let saves = storage.saved.count
        let photos = [PreparedPhoto(jpeg: Data([1, 2, 3]), width: 10, height: 20),
                      PreparedPhoto(jpeg: Data([4, 5, 6]), width: 30, height: 40)]
        try await driver.execute(
            .sendFeedback(
                sessionID: "ui-test-joined-session", message: "First then second", photos: photos
            )
        )
        let reservations = relay.requests.filter { $0.path.hasSuffix("/attachments") }
        let payload = try decryptResponse(relay.requests.last!.body, vault: driver.state.vault)
        let attachments = try XCTUnwrap(payload["attachments"] as? [[String: Any]])
        XCTAssertEqual(attachments.map { $0["id"] as! String }, reservations.map { $0.body["attachmentId"] as! String })
        XCTAssertEqual(attachments.map { $0["width"] as! Int }, [10, 30])
        XCTAssertEqual(payload["message"] as? String, "First then second")
        XCTAssertEqual(storage.saved.count, saves)
    }

    @MainActor
    func testPushRegistrationUsesSuppliedTokenAndEnvironment() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .registerPushToken(token: "captured-token", environment: .sandbox)
        )
        XCTAssertEqual(relay.requests.last!.body["token"] as? String, "captured-token")
        XCTAssertEqual(relay.requests.last!.body["environment"] as? String, "sandbox")
        XCTAssertTrue(storage.saved.isEmpty)
    }

    @MainActor
    func testSessionCommandFailuresReachModelAndPreserveState() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .joinSession(groupID: "ui-test-group", pairingURL: relay.pairingURL)
        )
        let model = AppModel(commandExecutor: driver.executor, initialState: driver.state)
        let initialSessions = model.sessions
        relay.failPath = "/api/sessions/ui-test-joined-session/responses"
        await model.respond(sessionID: "ui-test-joined-session", requestID: "A", optionID: "yes")
        XCTAssertNotNil(model.errorMessage)
        model.dismissError()
        let result = await model.sendFeedback(sessionID: "ui-test-joined-session", message: "message")
        XCTAssertEqual(result, .unknown)
        XCTAssertNotNil(model.errorMessage)
        model.dismissError()
        relay.failPath = nil
        storage.fail = true
        let changed = await model.setAttention(sessionID: "ui-test-joined-session", attention: true)
        XCTAssertFalse(changed)
        XCTAssertNotNil(model.errorMessage)
        XCTAssertEqual(model.sessions, initialSessions)
    }

    @MainActor
    func testModelCommandsWaitForSyncThenRunWithoutRejection() async throws {
        let fixture = try AppCommandFixture()
        let storage = AppCommandTestStorage()
        let executor = fixture.executor(storage: storage)
        let base = AppCommandTestTransport.response!
        let started = expectation(description: "sync is waiting")
        let submitted = expectation(description: "three model operations submitted")
        submitted.expectedFulfillmentCount = 3
        let release = DispatchSemaphore(value: 0)
        defer { release.signal() }
        var writes: [String] = []
        AppCommandTestTransport.response = { request in
            if request.url!.path.hasSuffix("/events") {
                started.fulfill()
                guard release.wait(timeout: .now() + 5) == .success else {
                    throw ProtocolError.invalidResponse("sync was not released by test")
                }
            }
            if request.httpMethod == "POST" {
                writes.append(request.url!.path)
                return try JSONSerialization.data(withJSONObject: ["expiresAt": fixture.expiresAt])
            }
            if request.httpMethod == "PUT" {
                writes.append(request.url!.path)
                return try JSONSerialization.data(withJSONObject: ["attention": true, "expiresAt": fixture.expiresAt])
            }
            return try base(request)
        }
        let model = AppModel(commandExecutor: executor, initialState: fixture.commandState())
        let sync = Task { await model.sync() }
        await fulfillment(of: [started], timeout: 2)
        let response = Task {
            submitted.fulfill()
            await model.respond(sessionID: "session", requestID: "A", optionID: "yes")
        }
        let attention = Task {
            submitted.fulfill()
            return await model.setAttention(sessionID: "session", attention: true)
        }
        let feedback = Task {
            submitted.fulfill()
            return await model.sendFeedback(sessionID: "session", message: "captured message")
        }
        await fulfillment(of: [submitted], timeout: 2)
        XCTAssertTrue(writes.isEmpty)
        XCTAssertNil(model.errorMessage)
        release.signal()
        await sync.value
        await response.value
        let attentionResult = await attention.value
        let feedbackResult = await feedback.value
        XCTAssertTrue(attentionResult)
        XCTAssertEqual(feedbackResult, .sent)
        XCTAssertEqual(writes.count, 3)
        XCTAssertNil(model.errorMessage)
    }

    @MainActor
    func testGroupCommandNetworkFailuresPropagateWithoutChangingSavedMembership() async throws {
        let (relay, driver, storage) = try commandFixture()
        try await driver.execute(
            .approveDeviceAddition(groupID: "ui-test-group", requestURL: relay.requestURL)
        )
        let initial = driver.state.vault
        let saves = storage.saved.count
        relay.failPath = "/api/groups/ui-test-group/devices/ui-test-other-device"
        do {
            try await driver.execute(
                .removeDevice(groupID: "ui-test-group", deviceID: "ui-test-other-device")
            )
            XCTFail("Removal failure must propagate")
        } catch let error as URLError { XCTAssertEqual(error.code, .notConnectedToInternet) }
        XCTAssertEqual(driver.state.vault, initial)
        XCTAssertEqual(storage.saved.count, saves)
        relay.failPath = "/api/groups/ui-test-group/devices/ui-test-device"
        do {
            try await driver.execute(.leaveDeviceGroup(groupID: "ui-test-group"))
            XCTFail("Leave failure must propagate")
        } catch let error as URLError { XCTAssertEqual(error.code, .notConnectedToInternet) }
        XCTAssertEqual(driver.state.vault, initial)
    }

    @MainActor
    func testInitializationPreparesIdentityAndSoloGroupBeforeCommands() async throws {
        let (relay, driver, storage) = try commandFixture()
        let state = try await driver.executor.initialize(nil, groupState: nil)
        XCTAssertNotNil(state.vault.identity.group)
        XCTAssertEqual(try XCTUnwrap(state.groupState).members.map(\.deviceID), ["ui-test-device"])
        XCTAssertEqual(storage.saved.last, state.vault)
        XCTAssertEqual(relay.requests.first!.path, "/api/devices")
    }

    @MainActor
    private func commandFixture() throws -> (
        CommandUITestRelay, AppCommandTestDriver, AppCommandTestStorage
    ) {
        let relay = try CommandUITestRelay()
        CommandUITestTransport.relay = relay
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [CommandUITestTransport.self]
        let storage = AppCommandTestStorage()
        let executor = AppCommandExecutor(
            api: APIClient(session: URLSession(configuration: configuration)), storage: storage
        )
        guard let groupState = relay.groups["ui-test-group"] else {
            throw ProtocolError.invalidResponse("test group state is unavailable")
        }
        let state = AppCommandState(
            vault: relay.vault, groupState: groupState, pendingDeviceRequest: nil
        )
        return (relay, AppCommandTestDriver(executor: executor, state: state), storage)
    }

    @MainActor
    private func decryptResponse(_ body: [String: Any], vault: Vault) throws -> [String: Any] {
        let session = vault.sessions[0]
        let timestamp = (body["keyTimestamp"] as! NSNumber).int64Value
        let responseID = body["responseId"] as! String
        let ciphertext = try Base64URL.decode(body["ciphertext"] as! String)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Base64URL.decode(body["nonce"] as! String)),
                                      ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
        let aad = Data("notify.guru/v4/response/\(session.sessionID)/\(session.groupID)/\(timestamp)/\(responseID)".utf8)
        let plaintext = try AES.GCM.open(box, using: SymmetricKey(data: session.keys[String(timestamp)]!), authenticating: aad)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: plaintext) as? [String: Any])
    }

}
