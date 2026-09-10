import Foundation
import XCTest
@testable import NotifyGuru

final class AppCommandQueueTests: XCTestCase {
    func testCommandSerializationPreservesTargetsAndImageOrder() throws {
        let commands: [AppCommand] = [
            .respond(sessionID: "session-A", requestID: "request-A", optionID: "yes"),
            .sendFeedback(sessionID: "session-A", message: "First, then second", photos: [
                PreparedPhoto(jpeg: Data([1, 2]), width: 10, height: 20),
                PreparedPhoto(jpeg: Data([3, 4]), width: 30, height: 40),
            ]),
        ]
        let restored = try JSONDecoder().decode(
            [AppCommand].self, from: JSONEncoder().encode(commands)
        )
        XCTAssertEqual(restored, commands)
    }

    @MainActor
    func testCommandQueueExecutesFixedTargetsInFIFOOrder() async throws {
        let fixture = try AppCommandFixture()
        let recorder = QueueRequestRecorder()
        let queue = makeQueue(recorder: recorder)
        let stateOwner = QueueTestStateOwner(state: fixture.commandState())
        let first = Task {
            try await queue.execute(pushCommand("A"), stateOwner: stateOwner)
        }
        await fulfillment(of: [recorder.firstStarted], timeout: 2)
        let submitted = expectation(description: "second command submitted")
        let second = Task {
            submitted.fulfill()
            return try await queue.execute(pushCommand("B"), stateOwner: stateOwner)
        }
        await fulfillment(of: [submitted], timeout: 2)
        XCTAssertEqual(recorder.tokens, ["A"])
        recorder.releaseFirst()
        _ = try await first.value
        _ = try await second.value
        XCTAssertEqual(recorder.tokens, ["A", "B"])
        XCTAssertEqual(recorder.maximumConcurrentRequests, 1)
    }

    @MainActor
    func testCommandQueueReturnsFailureAndContinues() async throws {
        let fixture = try AppCommandFixture()
        let recorder = QueueRequestRecorder(failFirst: true)
        let queue = makeQueue(recorder: recorder)
        let stateOwner = QueueTestStateOwner(state: fixture.commandState())
        let first = Task {
            try await queue.execute(pushCommand("A"), stateOwner: stateOwner)
        }
        await fulfillment(of: [recorder.firstStarted], timeout: 2)
        let submitted = expectation(description: "successor submitted")
        let second = Task {
            submitted.fulfill()
            return try await queue.execute(pushCommand("B"), stateOwner: stateOwner)
        }
        await fulfillment(of: [submitted], timeout: 2)
        recorder.releaseFirst()
        do {
            _ = try await first.value
            XCTFail("The executor error must reach the caller")
        } catch let error as URLError {
            XCTAssertEqual(error.code, .notConnectedToInternet)
        }
        _ = try await second.value
        XCTAssertEqual(recorder.tokens, ["A", "B"])
    }

    @MainActor
    func testCancelledWaitingCommandDoesNotExecuteOrBlockNextCommand() async throws {
        let fixture = try AppCommandFixture()
        let recorder = QueueRequestRecorder()
        let queue = makeQueue(recorder: recorder)
        let stateOwner = QueueTestStateOwner(state: fixture.commandState())
        let first = Task {
            try await queue.execute(pushCommand("A"), stateOwner: stateOwner)
        }
        await fulfillment(of: [recorder.firstStarted], timeout: 2)
        let submitted = expectation(description: "command submitted before cancellation")
        let cancelled = Task {
            submitted.fulfill()
            return try await queue.execute(pushCommand("B"), stateOwner: stateOwner)
        }
        await fulfillment(of: [submitted], timeout: 2)
        cancelled.cancel()
        let next = Task {
            try await queue.execute(pushCommand("C"), stateOwner: stateOwner)
        }
        recorder.releaseFirst()
        _ = try await first.value
        do {
            _ = try await cancelled.value
            XCTFail("Cancellation must reach the caller")
        } catch is CancellationError { }
        _ = try await next.value
        XCTAssertEqual(recorder.tokens, ["A", "C"])
    }

    @MainActor
    private func makeQueue(recorder: QueueRequestRecorder) -> AppCommandQueue {
        AppCommandTestTransport.response = recorder.response
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [AppCommandTestTransport.self]
        let executor = AppCommandExecutor(
            api: APIClient(session: URLSession(configuration: configuration)),
            storage: AppCommandTestStorage()
        )
        return AppCommandQueue(commandExecutor: executor)
    }

    private func pushCommand(_ token: String) -> AppCommand {
        .registerPushToken(token: token, environment: .sandbox)
    }
}

@MainActor
private final class QueueTestStateOwner: AppCommandStateOwner {
    private var state: AppCommandState

    init(state: AppCommandState) {
        self.state = state
    }

    func commandState() throws -> AppCommandState {
        state
    }

    func commit(_ nextState: AppCommandState) {
        state = nextState
    }
}

private final class QueueRequestRecorder: @unchecked Sendable {
    let firstStarted = XCTestExpectation(description: "first request started")
    private let lock = NSLock()
    private let firstRelease = DispatchSemaphore(value: 0)
    private let failFirst: Bool
    private var recordedTokens: [String] = []
    private var activeRequests = 0
    private var maximumActiveRequests = 0

    init(failFirst: Bool = false) {
        self.failFirst = failFirst
    }

    var tokens: [String] {
        lock.withLock { recordedTokens }
    }

    var maximumConcurrentRequests: Int {
        lock.withLock { maximumActiveRequests }
    }

    func releaseFirst() {
        firstRelease.signal()
    }

    func response(_ request: URLRequest) throws -> Data {
        let body = try JSONSerialization.jsonObject(
            with: CommandUITestRelay.bodyData(request)
        ) as! [String: Any]
        let token = body["token"] as! String
        let index = lock.withLock { () -> Int in
            recordedTokens.append(token)
            activeRequests += 1
            maximumActiveRequests = max(maximumActiveRequests, activeRequests)
            return recordedTokens.count
        }
        defer { lock.withLock { activeRequests -= 1 } }
        if index == 1 {
            firstStarted.fulfill()
            guard firstRelease.wait(timeout: .now() + 5) == .success else {
                throw ProtocolError.invalidResponse("test did not release first request")
            }
            if failFirst {
                throw URLError(.notConnectedToInternet)
            }
        }
        return try JSONSerialization.data(withJSONObject: ["updated": true])
    }
}
