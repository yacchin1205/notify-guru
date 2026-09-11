import Foundation
import OSLog

@MainActor
final class AppModel: ObservableObject, AppCommandStateOwner {
    var sessions: [SessionRecord] {
        vault?.sessions.sorted { ($0.updatedAt ?? 0) > ($1.updatedAt ?? 0) } ?? []
    }
    var groupDevices: [GroupDevice] { groupState?.members ?? [] }
    var currentKeyTimestamp: Int64? {
        groupState.flatMap(GroupKeyPolicy.selectUsableKey)?.timestamp
    }
    var hasDeviceGroup: Bool { vault?.identity.group != nil }
    var deviceID: String? { vault?.identity.deviceID }
    @Published private(set) var deviceRequestLink: String?
    @Published private(set) var isDeviceAdditionApprovalPending = false
    @Published private(set) var connectionState: ConnectionState = .preparing
    @Published private(set) var isReady = false
    @Published private(set) var startupErrorMessage: String?
    @Published private(set) var canResetLocalData = false
    @Published private(set) var operationErrors: [String] = []
    var errorMessage: String? {
        operationErrors.isEmpty ? nil : operationErrors.joined(separator: "\n\n")
    }
    @Published var noticeMessage: String?
    @Published private(set) var sessionSyncErrors: [String: String] = [:]

    private let keychain = KeychainVault()
    private let commandQueue: AppCommandQueue
    @Published private var vault: Vault?
    @Published private var groupState: DeviceGroupStateResult?
    @Published private var pendingDeviceRequest: DeviceRequestRecord?
    private var pendingDeviceAddition: String?
    private var pendingUniversalLinks: [URL] = []
    private let linkLogger = Logger(subsystem: "guru.notify.app", category: "LinkReception")
    private var pendingUniversalLinkTask: Task<Void, Never>?
    private var hasFinishedStarting = false
    private var didReportDisabledBadges = false

    init(
        commandExecutor: AppCommandExecutor? = nil,
        initialState: AppCommandState? = nil
    ) {
        let executor: AppCommandExecutor
        if let commandExecutor {
            executor = commandExecutor
        } else {
#if DEBUG
            if ProcessInfo.processInfo.arguments.contains(where: { ["-ui-test-session-history", "-ui-test-device-addition-approval", "-ui-test-session-link"].contains($0) }) {
                let configuration = URLSessionConfiguration.ephemeral
                configuration.protocolClasses = [CommandUITestTransport.self]
                executor = AppCommandExecutor(
                    api: APIClient(session: URLSession(configuration: configuration)), storage: CommandUITestStorage()
                )
            } else {
                executor = AppCommandExecutor()
            }
#else
            executor = AppCommandExecutor()
#endif
        }
        self.commandQueue = AppCommandQueue(commandExecutor: executor)
        if let initialState {
            vault = initialState.vault
            groupState = initialState.groupState
            pendingDeviceRequest = initialState.pendingDeviceRequest
            isReady = true
        }
    }

    private var isSessionHistoryUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-session-history")
#else
        false
#endif
    }

    private var isStartupScreenUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-startup-screen")
#else
        false
#endif
    }

    private var isStartupFailureUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-startup-error")
#else
        false
#endif
    }

    private var isRecoverableStartupFailureUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-recoverable-startup-error")
#else
        false
#endif
    }

    private var isMixedSessionInheritanceUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-mixed-session-inheritance")
#else
        false
#endif
    }

    private var isDeviceAdditionApprovalUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-device-addition-approval")
#else
        false
#endif
    }

    private var isSessionLinkUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-session-link")
#else
        false
#endif
    }

    var isAppBadgeUITest: Bool {
#if DEBUG
        ProcessInfo.processInfo.arguments.contains("-ui-test-app-badge")
#else
        false
#endif
    }

    var isAwaitingDeviceApproval: Bool { pendingDeviceRequest != nil }
    var deviceCount: Int { max(1, groupDevices.count) }
    var isSharingAcrossDevices: Bool { groupDevices.count > 1 }
    var deviceRequestWouldDiscardCurrentState: Bool { isSharingAcrossDevices || !sessions.isEmpty }

    func start() async {
        guard !isReady else { return }
#if DEBUG
        if isRecoverableStartupFailureUITest {
            failStartup("The saved notify.guru data on this device can no longer be opened.", canReset: true)
            return
        }
        if isMixedSessionInheritanceUITest {
            do {
                try startMixedSessionInheritanceUITest()
            } catch {
                failStartup(error.localizedDescription, canReset: false)
            }
            return
        }
        if isStartupScreenUITest {
            return
        }
        if isSessionHistoryUITest || isDeviceAdditionApprovalUITest || isSessionLinkUITest {
            startSessionHistoryUITest()
            if isDeviceAdditionApprovalUITest {
                do {
                    try stageDeviceAddition(
                        CommandUITestTransport.relay.requestURL
                    )
                } catch {
                    failStartup(error.localizedDescription, canReset: false)
                }
            }
            return
        }
#endif
        do {
            PushCoordinator.shared.onToken = { [weak self] token, environment in
                guard let self else { return }
                Task { await self.registerPushToken(token, environment: environment) }
            }
            PushCoordinator.shared.onFailure = { [weak self] error in self?.handlePushError(error) }
            try await commandQueue.initialize(
                keychain.load(), groupState: groupState, stateOwner: self
            )
            isReady = true
            await sync()
            await PushCoordinator.shared.resumeIfAuthorized()
            hasFinishedStarting = true
            await openPendingUniversalLink()
        } catch KeychainError.unsupportedVersion {
            failStartup(
                "The saved notify.guru data on this device can no longer be opened. Erase it to set up this device again; saved sessions will be removed.",
                canReset: true
            )
        } catch {
            failStartup(error.localizedDescription, canReset: false)
        }
    }

    func runSyncLoop() async {
        guard !isSessionHistoryUITest, !isDeviceAdditionApprovalUITest, !isSessionLinkUITest else { return }
        while !Task.isCancelled {
            await sync()
            do { try await Task.sleep(for: .seconds(2)) }
            catch is CancellationError { return }
            catch { show(error); return }
        }
    }

    func join(link: String) async -> Bool {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            let value = link.trimmingCharacters(in: .whitespacesAndNewlines)
            if URLComponents(string: value)?.path == "/device" {
                try stageDeviceAddition(value)
                return true
            }
            _ = try PairingLink(value)
            let groupID = try requiredGroupID()
            try await executeCommand(.joinSession(groupID: groupID, pairingURL: value))
            await enableNotifications()
            return true
        } catch { show(error); return false }
    }

    func confirmDeviceAddition() {
        guard let link = pendingDeviceAddition else {
            show(ProtocolError.invalidPairingLink("there is no device addition awaiting approval"))
            return
        }
        Task { _ = await approveDeviceAddition(link, clearPendingOnSuccess: true) }
    }

    func approvePendingDeviceAddition() async -> Bool {
        guard let link = pendingDeviceAddition else {
            show(ProtocolError.invalidPairingLink("there is no device addition awaiting approval"))
            return false
        }
        return await approveDeviceAddition(link, clearPendingOnSuccess: true)
    }

    private func approveDeviceAddition(_ link: String, clearPendingOnSuccess: Bool) async -> Bool {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            let groupID = try requiredGroupID()
            try await executeCommand(.approveDeviceAddition(groupID: groupID, requestURL: link))
            if clearPendingOnSuccess { clearPendingDeviceAddition() }
            return true
        } catch {
            show(error)
            return false
        }
    }

    func cancelDeviceAddition() { clearPendingDeviceAddition() }

    func openUniversalLink(_ url: URL) async {
        linkLogger.info("Queued received link")
        pendingUniversalLinks.append(url)
        schedulePendingUniversalLink()
    }

    func createDeviceRequest(discardingCurrentState: Bool = false) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            if let pendingDeviceRequest {
                deviceRequestLink = try deviceRequestURL(pendingDeviceRequest)
                return
            }
            let groupID = try requiredGroupID()
            try await executeCommand(.prepareDeviceGroupJoin(
                groupID: groupID, discardSavedSessions: discardingCurrentState
            ))
            guard let pendingDeviceRequest else {
                throw ProtocolError.invalidResponse("device request was not created")
            }
            deviceRequestLink = try deviceRequestURL(pendingDeviceRequest)
            clearPendingDeviceAddition()
        } catch { show(error) }
    }

    func removeDevice(_ deviceID: String) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            let groupID = try requiredGroupID()
            try await executeCommand(.removeDevice(groupID: groupID, deviceID: deviceID))
        } catch { show(error) }
    }

    func leaveDeviceGroup() async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            let groupID = try requiredGroupID()
            try await executeCommand(.leaveDeviceGroup(groupID: groupID))
            deviceRequestLink = nil
            clearPendingDeviceAddition()
        } catch { show(error) }
    }

    func respond(sessionID: String, requestID: String, optionID: String) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.respond(sessionID: sessionID, requestID: requestID, optionID: optionID))
        } catch { show(error) }
    }

    func dismissRequest(sessionID: String, requestID: String) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.dismissRequest(sessionID: sessionID, requestID: requestID))
        } catch {
            show(error)
        }
    }

    func dismissNotification(sessionID: String, notificationID: String) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.dismissNotification(sessionID: sessionID, notificationID: notificationID))
        } catch {
            show(error)
        }
    }

    func setAttention(sessionID: String, attention: Bool) async -> Bool {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.setAttention(sessionID: sessionID, enabled: attention))
            return true
        } catch { show(error); return false }
    }

    func sendFeedback(sessionID: String, message: String, photos: [PreparedPhoto] = []) async -> FeedbackSendResult {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.sendFeedback(sessionID: sessionID, message: message, photos: photos))
            return .sent
        } catch {
            show(error)
            return error is FeedbackResultUnknown ? .unknown : .failed
        }
    }

    func enableNotifications() async {
        do {
            _ = try await PushCoordinator.shared.enable()
            didReportDisabledBadges = false
        } catch {
            handlePushError(error)
        }
    }

    func resumeNotifications() async { await PushCoordinator.shared.resumeIfAuthorized() }
    func dismissError() { operationErrors.removeAll() }
    func dismissNotice() { noticeMessage = nil }

#if DEBUG
    func completeStartupUITest() {
        guard isStartupScreenUITest else { return }
        if isStartupFailureUITest {
            failStartup("Startup failed for UI testing", canReset: false)
        } else {
            startSessionHistoryUITest()
        }
    }
#endif

    private func openPendingUniversalLink() async {
        while !pendingUniversalLinks.isEmpty {
            let url = pendingUniversalLinks.removeFirst()
            linkLogger.info("Starting queued link operation")
            let joined = await join(link: url.absoluteString)
            linkLogger.info("Queued link operation completed; succeeded: \(joined)")
        }
    }

    private func schedulePendingUniversalLink() {
        guard hasFinishedStarting, !pendingUniversalLinks.isEmpty, pendingUniversalLinkTask == nil else { return }
        pendingUniversalLinkTask = Task { @MainActor [weak self] in
            guard let self else { return }
            await self.openPendingUniversalLink()
            self.pendingUniversalLinkTask = nil
        }
    }

    func resetLocalData() async {
        guard canResetLocalData else { return }
#if DEBUG
        if isRecoverableStartupFailureUITest {
            vault = nil
            clearPublishedGroupState()
            startupErrorMessage = nil
            canResetLocalData = false
            connectionState = .preparing
            hasFinishedStarting = false
            startSessionHistoryUITest()
            return
        }
#endif
        do {
            try keychain.remove()
            vault = nil
            clearPublishedGroupState()
            startupErrorMessage = nil
            canResetLocalData = false
            connectionState = .preparing
            hasFinishedStarting = false
            await start()
        } catch {
            failStartup(error.localizedDescription, canReset: true)
        }
    }

    func sync() async {
        guard !isSessionHistoryUITest, !isRecoverableStartupFailureUITest, !isMixedSessionInheritanceUITest,
              !isDeviceAdditionApprovalUITest, !isSessionLinkUITest else { return }
        guard isReady else { return }
        let previousConnectionState = connectionState
        connectionState = .syncing
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.synchronize)
            connectionState = .current
        } catch where Task.isCancelled && Self.isCancellation(error) {
            connectionState = previousConnectionState
            return
        } catch {
            show(error)
        }
        do {
            deviceRequestLink = try pendingDeviceRequest.map(deviceRequestURL)
        } catch {
            show(error)
        }
    }

    private func stageDeviceAddition(_ value: String) throws {
        _ = try DeviceRequestLink(value)
        guard pendingDeviceAddition == nil else {
            throw ProtocolError.invalidPairingLink("another device addition is awaiting approval")
        }
        pendingDeviceAddition = value
        isDeviceAdditionApprovalPending = true
    }

    private func clearPendingDeviceAddition() {
        pendingDeviceAddition = nil
        isDeviceAdditionApprovalPending = false
    }

    private func registerPushToken(_ token: String, environment: PushEnvironment) async {
        defer {
            schedulePendingUniversalLink()
        }
        do {
            try await executeCommand(.registerPushToken(token: token, environment: environment))
        } catch { show(error) }
    }

    private func executeCommand(_ command: AppCommand) async throws {
        sessionSyncErrors = [:]
        let result: AppCommandResult
        do {
            result = try await commandQueue.execute(command, stateOwner: self)
        } catch let error as SessionSynchronizationError {
            sessionSyncErrors[error.sessionID] = error.underlyingError.localizedDescription
            throw error
        }
        for change in result.changes {
            switch change {
            case .deviceAdded:
                await enableNotifications()
            case .deviceRequestExpired:
                noticeMessage = "The add-to-group link expired. This device is now used on its own."
            case .deviceRemoved:
                clearPendingDeviceAddition()
                noticeMessage = "This device was removed from its group. It is now used on its own."
            }
        }
    }

    func commandState() throws -> AppCommandState {
        AppCommandState(
            vault: try requiredVault(),
            groupState: groupState,
            pendingDeviceRequest: pendingDeviceRequest
        )
    }

    func commit(_ nextState: AppCommandState) {
        vault = nextState.vault
        groupState = nextState.groupState
        pendingDeviceRequest = nextState.pendingDeviceRequest
    }

    private func deviceRequestURL(_ request: DeviceRequestRecord) throws -> String {
        var fragment = URLComponents(); fragment.queryItems = [
            URLQueryItem(name: "v", value: "3"), URLQueryItem(name: "r", value: request.requestID),
            URLQueryItem(name: "a", value: request.authSecret), URLQueryItem(name: "h", value: request.requestHash),
        ]
        var result = URLComponents(string: "https://notify.guru/device")!
        result.percentEncodedFragment = fragment.percentEncodedQuery
        guard let value = result.url?.absoluteString else { throw ProtocolError.invalidResponse("could not create the link for adding this device") }
        return value
    }

    private func clearPublishedGroupState() {
        groupState = nil
        pendingDeviceRequest = nil; deviceRequestLink = nil
        clearPendingDeviceAddition()
    }

    private func requiredGroupID() throws -> String {
        guard let groupID = try requiredVault().identity.group?.groupID else {
            throw ProtocolError.invalidResponse("device group is unavailable")
        }
        return groupID
    }

    private func requiredVault() throws -> Vault {
        guard let vault else { throw ProtocolError.invalidResponse("secure storage is not ready") }
        return vault
    }

    private func failStartup(_ message: String, canReset: Bool) {
        hasFinishedStarting = false
        startupErrorMessage = message
        canResetLocalData = canReset
        connectionState = .failed
    }

    private func show(_ error: Error) {
        reportError(error.localizedDescription)
        connectionState = .failed
    }

    func reportError(_ message: String) {
        if !operationErrors.contains(message) { operationErrors.append(message) }
    }

    nonisolated private static func isCancellation(_ error: Error) -> Bool {
        error is CancellationError || (error as? URLError)?.code == .cancelled
    }

    private func handlePushError(_ error: Error) {
        if case PushError.badgesDisabled = error {
            guard !didReportDisabledBadges else { return }
            didReportDisabledBadges = true
            noticeMessage = "App icon badges are turned off. To see the number of unresolved items on the Home Screen, enable Badges in Settings > Notifications > notify.guru."
            return
        }
        show(error)
    }

#if DEBUG
    private func startMixedSessionInheritanceUITest() throws {
        let groupID = "ui-test-mixed-group"
        var identity = try CryptoEngine.createIdentity()
        identity.deviceID = "ui-test-mixed-device"
        var removedIdentity = try CryptoEngine.createIdentity()
        removedIdentity.deviceID = "ui-test-removed-device"
        let member = TransitionMember(
            deviceID: identity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
        )
        let removedMember = TransitionMember(
            deviceID: removedIdentity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: removedIdentity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: removedIdentity)
        )
        let draft = CryptoEngine.createGroupKey()
        let packages = try [member, removedMember].map { value in
            try CryptoEngine.createKeyPackage(
                groupID: groupID, key: draft, deviceID: value.deviceID,
                encryptionPublicKey: value.encryptionPublicKey
            )
        }
        let transition = try CryptoEngine.createGroupTransition(
            groupID: groupID, identity: identity, groupKey: draft, previous: nil,
            members: [member, removedMember], packages: packages, recreated: true, now: 10
        )
        let key = GroupKey(
            timestamp: transition.timestamp, publicKey: draft.publicKey,
            privateKey: draft.privateKey, transitionHash: transition.transitionHash
        )
        identity.group = DeviceGroup(
            groupID: groupID, keys: [String(key.timestamp): key],
            rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash
        )
        removedIdentity.group = DeviceGroup(
            groupID: groupID, keys: [String(key.timestamp): key],
            rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash
        )
        let descriptor = try CryptoEngine.createSessionDescriptor(
            identity: identity, key: key, sessionID: "authenticated-v4-session",
            groupID: groupID, creatorPublicKey: draft.publicKey
        )
        let removedDescriptor = try CryptoEngine.createSessionDescriptor(
            identity: removedIdentity, key: key, sessionID: "removed-actor-session",
            groupID: groupID, creatorPublicKey: draft.publicKey
        )
        let removalDraft = CryptoEngine.createGroupKey()
        let removalPackage = try CryptoEngine.createKeyPackage(
            groupID: groupID, key: removalDraft, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let removal = try CryptoEngine.createGroupTransition(
            groupID: groupID, identity: identity, groupKey: removalDraft, previous: transition,
            members: [member], packages: [removalPackage], recreated: true, now: 11
        )
        identity.group?.keys[String(removal.timestamp)] = GroupKey(
            timestamp: removal.timestamp, publicKey: removalDraft.publicKey,
            privateKey: removalDraft.privateKey, transitionHash: removal.transitionHash
        )
        let readdedDraft = CryptoEngine.createGroupKey()
        let readdedPackages = try [member, removedMember].map { value in
            try CryptoEngine.createKeyPackage(
                groupID: groupID, key: readdedDraft, deviceID: value.deviceID,
                encryptionPublicKey: value.encryptionPublicKey
            )
        }
        let readded = try CryptoEngine.createGroupTransition(
            groupID: groupID, identity: identity, groupKey: readdedDraft, previous: removal,
            members: [member, removedMember], packages: readdedPackages, recreated: false, now: 12
        )
        identity.group?.keys[String(readded.timestamp)] = GroupKey(
            timestamp: readded.timestamp, publicKey: readdedDraft.publicKey,
            privateKey: readdedDraft.privateKey, transitionHash: readded.transitionHash
        )
        identity.group?.headTransitionHash = readded.transitionHash
        let legacy = GroupSessionResult(
            protocolVersion: 3, sessionID: "legacy-v3-session", groupID: groupID,
            creatorPublicKey: draft.publicKey,
            expiresAt: Self.currentTimeMilliseconds() + 86_400_000, keyTimestamp: nil,
            transitionHash: nil, actorDeviceID: nil, actorSignature: nil, continuitySignature: nil
        )
        let signed = GroupSessionResult(
            protocolVersion: 4, sessionID: descriptor.sessionID, groupID: descriptor.groupID,
            creatorPublicKey: descriptor.creatorPublicKey,
            expiresAt: Self.currentTimeMilliseconds() + 86_400_000,
            keyTimestamp: descriptor.keyTimestamp, transitionHash: descriptor.transitionHash,
            actorDeviceID: descriptor.actorDeviceID, actorSignature: descriptor.actorSignature,
            continuitySignature: descriptor.continuitySignature
        )
        let removedSigned = GroupSessionResult(
            protocolVersion: 4, sessionID: removedDescriptor.sessionID, groupID: removedDescriptor.groupID,
            creatorPublicKey: removedDescriptor.creatorPublicKey,
            expiresAt: Self.currentTimeMilliseconds() + 86_400_000,
            keyTimestamp: removedDescriptor.keyTimestamp, transitionHash: removedDescriptor.transitionHash,
            actorDeviceID: removedDescriptor.actorDeviceID, actorSignature: removedDescriptor.actorSignature,
            continuitySignature: removedDescriptor.continuitySignature
        )
        let authenticatedGroupState = DeviceGroupStateResult(
            groupID: groupID,
            members: [member, removedMember].map { value in
                GroupDevice(
                    deviceID: value.deviceID, encryptionPublicKey: value.encryptionPublicKey,
                    signingPublicKey: value.signingPublicKey, addedAt: 0
                )
            },
            keys: [transition, removal, readded], packages: [], sessions: [legacy, signed, removedSigned]
        )
        groupState = authenticatedGroupState
        let attackerKey = CryptoEngine.createGroupKey()
        let stale = SessionRecord(
            protocolVersion: 4, sessionID: signed.sessionID, groupID: groupID,
            creatorPublicKey: attackerKey.publicKey, keys: [:], cursor: 0,
            title: "Tampered local session", status: "Unsafe", notifications: [],
            request: nil, requestKeyTimestamp: nil, color: nil,
            updatedAt: Self.currentTimeMilliseconds(), expiresAt: signed.expiresAt
        )
        var current = Vault(version: 4, identity: identity, sessions: [stale])
        guard try AppCommandExecutor.inheritSessions(
            &current, groupState: authenticatedGroupState
        ),
              current.sessions.count == 2,
              let signedIndex = current.sessions.firstIndex(where: { $0.sessionID == signed.sessionID }),
              let removedIndex = current.sessions.firstIndex(where: { $0.sessionID == removedSigned.sessionID }),
              current.sessions[signedIndex].creatorPublicKey == signed.creatorPublicKey,
              !current.sessions[signedIndex].keys.isEmpty,
              !current.sessions[removedIndex].keys.isEmpty else {
            throw ProtocolError.crypto("authenticated sessions were not inherited")
        }
        current.sessions[signedIndex].title = "Authenticated v4 session"
        current.sessions[signedIndex].status = "Connected securely"
        current.sessions[signedIndex].color = "#d9f2d0"
        current.sessions[removedIndex].title = "Session retained after signer removal"
        current.sessions[removedIndex].status = "Connected securely"
        vault = current
        connectionState = .current
        isReady = true
        hasFinishedStarting = true
    }

    private func startSessionHistoryUITest() {
        do {
            let relay = try CommandUITestRelay()
            CommandUITestTransport.relay = relay
            if ProcessInfo.processInfo.arguments.contains("-ui-test-dismiss-error") ||
                ProcessInfo.processInfo.arguments.contains("-ui-test-response-error") {
                relay.failPath = "/api/sessions/ui-test-session/responses"
            }
            if ProcessInfo.processInfo.arguments.contains("-ui-test-device-addition-error") {
                relay.failPath = "/api/groups/ui-test-group/device-requests/ui-test-device-request/approve"
                relay.failure = ProtocolError.invalidResponse("Device addition failed for UI testing")
            }
            let now = Self.currentTimeMilliseconds()
            let group = relay.vault.identity.group!
            let key = group.keys.values.first!
            let sessionKey = try CryptoEngine.deriveSessionKey(key: key, creatorPublicKey: key.publicKey,
                sessionID: "ui-test-session", groupID: group.groupID, protocolVersion: 4)
            let session = SessionRecord(
                protocolVersion: 4, sessionID: "ui-test-session", groupID: "ui-test-group",
                creatorPublicKey: key.publicKey, keys: [String(key.timestamp): sessionKey], cursor: 3,
                title: "UI improvement test", status: "Working",
                notifications: [
                    SessionNotification(
                        id: "notice-1", message: "First accumulated notice",
                        createdAt: now - 2_000, serverItemID: "notice-1"
                    ),
                    SessionNotification(
                        id: "notice-2", message: "Second accumulated notice",
                        createdAt: now - 20 * 60_000, serverItemID: "notice-2"
                    ),
                ],
                request: SessionRequest(
                    id: "request-1", prompt: "Continue the meeting?",
                    options: [SessionChoice(id: "yes", label: "Yes"), SessionChoice(id: "no", label: "No")],
                    createdAt: now - 30_000, serverItemID: "request-1"
                ),
                requestKeyTimestamp: 42, color: "#d9f2d0", updatedAt: now - 20 * 60_000,
                expiresAt: now + 86_400_000
            )
            try relay.addSession(session)
            var uiTestSessions = [session]
            if ProcessInfo.processInfo.arguments.contains("-ui-test-photo-message") {
                uiTestSessions[0].notifications = []
                uiTestSessions[0].request = nil
                uiTestSessions[0].requestKeyTimestamp = nil
            } else if ProcessInfo.processInfo.arguments.contains("-ui-test-ipad-layout") {
                uiTestSessions[0].notifications = []
                uiTestSessions[0].request = nil
                uiTestSessions[0].requestKeyTimestamp = nil
                uiTestSessions.append(contentsOf: [
                    SessionRecord(
                        protocolVersion: 3, sessionID: "ui-test-build", groupID: "ui-test-group",
                        creatorPublicKey: "unused", keys: ["42": Data(repeating: 7, count: 32)], cursor: 1,
                        title: "Build pipeline", status: "Building", notifications: [], request: nil,
                        requestKeyTimestamp: nil, color: "#d6e4ff", updatedAt: now - 5 * 60_000,
                        expiresAt: now + 86_400_000
                    ),
                    SessionRecord(
                        protocolVersion: 3, sessionID: "ui-test-audit", groupID: "ui-test-group",
                        creatorPublicKey: "unused", keys: ["42": Data(repeating: 7, count: 32)], cursor: 1,
                        title: "Security audit", status: "Reviewing", notifications: [], request: nil,
                        requestKeyTimestamp: nil, color: "#f2d7ee", updatedAt: now - 10 * 60_000,
                        expiresAt: now + 86_400_000
                    ),
                ])
            }
            let identity = relay.vault.identity
            let current = Vault(version: 4, identity: identity, sessions: uiTestSessions)
            vault = current
            if ProcessInfo.processInfo.arguments.contains("-ui-test-session-sync-error") {
                sessionSyncErrors[session.sessionID] = "Invalid server response: object fields do not match the protocol"
            }
            guard let authenticatedGroupState = relay.groups[group.groupID] else {
                throw ProtocolError.invalidResponse("UI test group state is unavailable")
            }
            groupState = authenticatedGroupState
            connectionState = .current
            isReady = true
            hasFinishedStarting = true
        } catch {
            failStartup(error.localizedDescription, canReset: false)
        }
    }
#endif

    nonisolated static func pruningExpiredSessions(from vault: Vault, nowMilliseconds: Int64) -> Vault {
        var result = vault; result.sessions.removeAll { $0.expiresAt <= nowMilliseconds }; return result
    }

    nonisolated private static func currentTimeMilliseconds() -> Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }
}
