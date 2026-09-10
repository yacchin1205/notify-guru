import Foundation

@MainActor
/// This class must never retain mutable application state. notify.guru rotates
/// and redistributes keys associated with sessions as it operates, so concurrent
/// operations using different state snapshots can destroy the authenticated state.
/// Every application operation must be serialized here. Queue bookkeeping such as
/// the execution slot and waiting commands is scheduling state, not application state.
final class AppCommandQueue {
    private let commandExecutor: AppCommandExecutor
    private var isExecuting = false
    private var waiting: [CheckedContinuation<Void, Never>] = []

    init(commandExecutor: AppCommandExecutor) {
        self.commandExecutor = commandExecutor
    }

    func execute(
        _ command: AppCommand,
        stateOwner: any AppCommandStateOwner
    ) async throws -> AppCommandResult {
        await acquireExecutionSlot()
        defer { releaseExecutionSlot() }
        try Task.checkCancellation()
        let result = try await commandExecutor.execute(
            command, state: stateOwner.commandState()
        )
        stateOwner.commit(result.nextState)
        return result
    }

    func initialize(
        _ loaded: Vault?,
        groupState: DeviceGroupStateResult?,
        stateOwner: any AppCommandStateOwner
    ) async throws {
        await acquireExecutionSlot()
        defer { releaseExecutionSlot() }
        try Task.checkCancellation()
        let nextState = try await commandExecutor.initialize(
            loaded, groupState: groupState
        )
        stateOwner.commit(nextState)
    }

    private func acquireExecutionSlot() async {
        await withCheckedContinuation { continuation in
            if isExecuting {
                waiting.append(continuation)
            } else {
                isExecuting = true
                continuation.resume()
            }
        }
    }

    private func releaseExecutionSlot() {
        if waiting.isEmpty {
            isExecuting = false
        } else {
            waiting.removeFirst().resume()
        }
    }
}
