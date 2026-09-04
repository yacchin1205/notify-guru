import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var sessions: [SessionRecord] = []
    @Published private(set) var groupDevices: [GroupDevice] = []
    @Published private(set) var currentKeyTimestamp: Int64?
    @Published private(set) var hasDeviceGroup = false
    @Published private(set) var deviceID: String?
    @Published private(set) var deviceRequestLink: String?
    @Published private(set) var isDeviceAdditionApprovalPending = false
    @Published private(set) var connectionState: ConnectionState = .preparing
    @Published private(set) var isReady = false
    @Published private(set) var startupErrorMessage: String?
    @Published private(set) var canResetLocalData = false
    @Published var errorMessage: String?
    @Published var noticeMessage: String?
    @Published private(set) var sessionSyncErrors: [String: String] = [:]

    private let keychain = KeychainVault()
    private let api = APIClient()
    private var vault: Vault?
    private var groupState: DeviceGroupStateResult?
    private var pendingDeviceRequest: DeviceRequestRecord?
    private var pendingDeviceAddition: DeviceRequestLink?
    private var pendingUniversalLink: URL?
    private var hasFinishedStarting = false
    private var isSyncing = false
    private var isStateActionInProgress = false
    private var didReportDisabledBadges = false

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
                        DeviceRequestLink("https://notify.guru/device#v=3&r=ui-test-device-request&a=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&h=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
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
            let loaded = try keychain.load()
            var current: Vault
            if let loaded {
                current = Self.pruningExpiredSessions(from: loaded, nowMilliseconds: Self.currentTimeMilliseconds())
            } else {
                var identity = try CryptoEngine.createIdentity()
                identity.deviceID = try await api.registerDevice(identity: identity)
                current = Vault(version: 4, identity: identity, sessions: [])
            }
            if current.identity.group == nil { try await createSoloGroup(&current) }
            try persist(current)
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
        guard !isSyncing, !isStateActionInProgress else { return false }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            let value = link.trimmingCharacters(in: .whitespacesAndNewlines)
            if URLComponents(string: value)?.path == "/device" {
                try stageDeviceAddition(DeviceRequestLink(value))
                errorMessage = nil
                return true
            } else {
                let pairing = try PairingLink(value)
#if DEBUG
                if isSessionLinkUITest {
                    errorMessage = nil
                    return true
                }
#endif
                try await joinSession(pairing)
            }
            errorMessage = nil
            await sync()
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

    private func approveDeviceAddition(_ link: DeviceRequestLink, clearPendingOnSuccess: Bool) async -> Bool {
#if DEBUG
        if isDeviceAdditionApprovalUITest {
            if ProcessInfo.processInfo.arguments.contains("-ui-test-device-addition-error") {
                show(ProtocolError.invalidResponse("Device addition failed for UI testing"))
                return false
            }
            if clearPendingOnSuccess { clearPendingDeviceAddition() }
            return true
        }
#endif
        guard !isSyncing, !isStateActionInProgress else {
            show(ProtocolError.invalidResponse("device state is being synchronized; try again shortly"))
            return false
        }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            try await approveDeviceRequest(link)
            if clearPendingOnSuccess { clearPendingDeviceAddition() }
            errorMessage = nil
            await sync()
            return true
        } catch {
            show(error)
            return false
        }
    }

    func cancelDeviceAddition() { clearPendingDeviceAddition() }

    func openUniversalLink(_ url: URL) async {
        guard !hasFinishedStarting else {
            _ = await join(link: url.absoluteString)
            return
        }
        pendingUniversalLink = url
    }

    func createDeviceRequest(discardingCurrentState: Bool = false) async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            if let pendingDeviceRequest {
                deviceRequestLink = try deviceRequestURL(pendingDeviceRequest)
                return
            }
            try await synchronizeGroup(&current)
            if try inheritSessions(&current) { try persist(current) }
            if deviceRequestWouldDiscardCurrentState && !discardingCurrentState {
                throw ProtocolError.invalidResponse("confirm removing this device from its current group and deleting its saved sessions")
            }
            if let groupID = current.identity.group?.groupID {
                guard let state = groupState, let head = current.identity.group?.headTransitionHash else {
                    throw ProtocolError.crypto("group transition head is unavailable")
                }
                if state.members.count == 1 {
                    try await api.abandonGroup(identity: current.identity, headTransitionHash: head)
                } else {
                    let update = try createSelfRemovalTransition(
                        current: current,
                        members: state.members.filter { $0.deviceID != current.identity.deviceID }.map(transitionMember)
                    )
                    try await api.removeDevice(
                        identity: current.identity, deviceID: current.identity.deviceID,
                        transition: update.transition, packages: update.packages
                    )
                }
                current = Self.detachingFromDeviceGroup(current, groupID: groupID)
                clearPublishedGroupState()
            }
            let requestID = try CryptoEngine.randomID()
            let authSecret = try CryptoEngine.randomToken()
            let created = try await api.createDeviceRequest(
                identity: current.identity, requestID: requestID, authSecret: authSecret
            )
            pendingDeviceRequest = created
            try persist(current)
            deviceRequestLink = try deviceRequestURL(created)
            errorMessage = nil
        } catch { show(error) }
    }

    func removeDevice(_ deviceID: String) async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard let state = groupState else { throw ProtocolError.crypto("group state is unavailable") }
            let update = try createMembershipTransition(
                current: current,
                members: state.members.filter { $0.deviceID != deviceID }.map(transitionMember),
                recreated: true
            )
            try await api.removeDevice(
                identity: current.identity, deviceID: deviceID,
                transition: update.transition, packages: update.packages
            )
            try storeTransitionKey(update, in: &current)
            try await synchronizeGroup(&current)
            try await ensureExactGroupKey(&current)
            _ = try inheritSessions(&current)
            try persist(current)
        } catch { show(error) }
    }

    func leaveDeviceGroup() async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard groupDevices.count > 1, let groupID = current.identity.group?.groupID else {
                throw ProtocolError.invalidResponse("this device cannot be removed from a group with no other devices")
            }
            guard let state = groupState else { throw ProtocolError.crypto("group state is unavailable") }
            let update = try createSelfRemovalTransition(
                current: current,
                members: state.members.filter { $0.deviceID != current.identity.deviceID }.map(transitionMember)
            )
            try await api.removeDevice(
                identity: current.identity, deviceID: current.identity.deviceID,
                transition: update.transition, packages: update.packages
            )
            current = Self.detachingFromDeviceGroup(current, groupID: groupID)
            clearPublishedGroupState()
            try await createSoloGroup(&current)
            try persist(current)
        } catch { show(error) }
    }

    func respond(sessionID: String, optionID: String) async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let request = current.sessions[index].request,
                  let group = current.identity.group,
                  let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
                throw ProtocolError.invalidResponse("request is no longer available")
            }
            try populateSessionKeys(&current.sessions[index], group: group)
            let timestamp = key.timestamp
            let responseID = try CryptoEngine.randomID()
            let payload = try CryptoEngine.encryptResponse(
                session: current.sessions[index], timestamp: timestamp, responseID: responseID,
                requestID: request.id, optionID: optionID, createdAt: ISO8601DateFormatter().string(from: Date())
            )
            current.sessions[index].expiresAt = try await api.postResponse(
                session: current.sessions[index], identity: current.identity, timestamp: timestamp,
                responseID: responseID, itemID: request.serverItemID, payload: payload
            )
            current.sessions[index].request = nil
            current.sessions[index].requestKeyTimestamp = nil
            current.sessions[index].status = "Response sent"
            try persist(current)
        } catch { show(error) }
    }

    func dismissRequest(sessionID: String) async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let request = current.sessions[index].request,
                  let group = current.identity.group,
                  let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
                throw ProtocolError.invalidResponse("request is no longer available")
            }
            try populateSessionKeys(&current.sessions[index], group: group)
            let timestamp = key.timestamp
#if DEBUG
            if isSessionHistoryUITest {
                if ProcessInfo.processInfo.arguments.contains("-ui-test-dismiss-error") {
                    throw URLError(.notConnectedToInternet)
                }
                current.sessions[index].request = nil
                current.sessions[index].requestKeyTimestamp = nil
                current.sessions[index].status = "Request dismissed"
                try persist(current)
                return
            }
#endif
            let responseID = try CryptoEngine.randomID()
            let createdAt = RFC3339.string(from: Date())
            let payload = if let itemID = request.serverItemID {
                try CryptoEngine.encryptDismiss(
                    session: current.sessions[index], timestamp: timestamp, responseID: responseID,
                    eventID: itemID, createdAt: createdAt
                )
            } else {
                try CryptoEngine.encryptLegacyRequestDismiss(
                    session: current.sessions[index], timestamp: timestamp, responseID: responseID,
                    requestID: request.id, createdAt: createdAt
                )
            }
            current.sessions[index].expiresAt = try await api.postResponse(
                session: current.sessions[index], identity: current.identity, timestamp: timestamp,
                responseID: responseID, itemID: request.serverItemID, payload: payload
            )
            current.sessions[index].request = nil
            current.sessions[index].requestKeyTimestamp = nil
            current.sessions[index].status = "Request dismissed"
            try persist(current)
        } catch { show(error) }
    }

    func dismissNotification(sessionID: String, notificationID: String) async {
        guard !isSyncing, !isStateActionInProgress else { return }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard let sessionIndex = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let notificationIndex = current.sessions[sessionIndex].notifications.firstIndex(where: { $0.id == notificationID }) else {
                throw ProtocolError.invalidResponse("notification is no longer available")
            }
            let notification = current.sessions[sessionIndex].notifications[notificationIndex]
            if let itemID = notification.serverItemID {
                guard let group = current.identity.group,
                      let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
                    throw ProtocolError.invalidResponse("notification dismissal key is unavailable")
                }
                try populateSessionKeys(&current.sessions[sessionIndex], group: group)
                let responseID = try CryptoEngine.randomID()
                let payload = try CryptoEngine.encryptDismiss(
                    session: current.sessions[sessionIndex], timestamp: key.timestamp, responseID: responseID,
                    eventID: itemID, createdAt: RFC3339.string(from: Date())
                )
                current.sessions[sessionIndex].expiresAt = try await api.postResponse(
                    session: current.sessions[sessionIndex], identity: current.identity, timestamp: key.timestamp,
                    responseID: responseID, itemID: itemID, payload: payload
                )
            }
            current.sessions[sessionIndex].notifications.remove(at: notificationIndex)
            try persist(current)
        } catch { show(error) }
    }

    func setAttention(sessionID: String, attention: Bool) async -> Bool {
        guard !isSyncing, !isStateActionInProgress else { return false }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }) else {
                throw ProtocolError.invalidResponse("session is no longer available")
            }
#if DEBUG
            if isSessionHistoryUITest {
                current.sessions[index].attention = attention
                try persist(current)
                return true
            }
#endif
            try await api.setAttention(session: current.sessions[index], identity: current.identity, attention: attention)
            current.sessions[index].attention = attention
            try persist(current)
            return true
        } catch { show(error); return false }
    }

    func sendFeedback(sessionID: String, message: String, photo: PreparedPhoto? = nil) async -> Bool {
        guard !isSyncing, !isStateActionInProgress else { return false }
        isStateActionInProgress = true
        defer { isStateActionInProgress = false }
        do {
            let text = message.trimmingCharacters(in: .whitespacesAndNewlines)
            guard text.utf8.count <= 20_000, !text.isEmpty || photo != nil else {
                throw ProtocolError.invalidResponse("a message or photo is required, and the message must not exceed 20000 bytes")
            }
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let group = current.identity.group,
                  let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
                throw ProtocolError.invalidResponse("session feedback key is unavailable")
            }
            try populateSessionKeys(&current.sessions[index], group: group)
            guard current.sessions[index].protocolVersion == 4 || photo == nil else {
                throw ProtocolError.invalidResponse("this session does not support photo attachments")
            }
            let responseID = try CryptoEngine.randomID()
            var attachment: EncryptedAttachment?
            if let photo {
                let attachmentID = try CryptoEngine.randomID()
                attachment = try CryptoEngine.encryptAttachment(
                    groupKey: key, creatorPublicKey: current.sessions[index].creatorPublicKey,
                    sessionID: current.sessions[index].sessionID, groupID: current.sessions[index].groupID,
                    responseID: responseID, attachmentID: attachmentID,
                    jpeg: photo.jpeg, width: photo.width, height: photo.height
                )
                let reservation = try await api.reserveAttachment(
                    session: current.sessions[index], identity: current.identity, timestamp: key.timestamp,
                    responseID: responseID, attachment: attachment!
                )
                try await api.uploadAttachment(session: current.sessions[index], attachment: attachment!, reservation: reservation)
            }
            let payload = try CryptoEngine.encryptFeedback(
                session: current.sessions[index], timestamp: key.timestamp, responseID: responseID,
                message: text.isEmpty ? nil : text, attachment: attachment?.manifest,
                createdAt: RFC3339.string(from: Date())
            )
            current.sessions[index].expiresAt = try await api.postResponse(
                session: current.sessions[index], identity: current.identity, timestamp: key.timestamp,
                responseID: responseID, itemID: nil, attachmentID: attachment?.manifest.id, payload: payload
            )
            try persist(current)
            return true
        } catch {
            show(error)
            return false
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
    func dismissError() { errorMessage = nil }
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
        guard let url = pendingUniversalLink else { return }
        pendingUniversalLink = nil
        _ = await join(link: url.absoluteString)
    }

    func resetLocalData() async {
        guard canResetLocalData else { return }
#if DEBUG
        if isRecoverableStartupFailureUITest {
            vault = nil
            sessions = []
            clearPublishedGroupState()
            hasDeviceGroup = false
            deviceID = nil
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
            sessions = []
            clearPublishedGroupState()
            hasDeviceGroup = false
            deviceID = nil
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
        guard isReady, !isSyncing, !isStateActionInProgress else { return }
        isSyncing = true; connectionState = .syncing
        defer { isSyncing = false }
        do {
            var current = try requiredVault()
            let pruned = Self.pruningExpiredSessions(from: current, nowMilliseconds: Self.currentTimeMilliseconds())
            if pruned != current {
                current = pruned
                try persist(current)
            }
            try await pollDeviceRequest(&current)
            if current.identity.group != nil {
                try await synchronizeGroup(&current)
                try await ensureExactGroupKey(&current)
                if try inheritSessions(&current) { try persist(current) }
                let sessionIDs = current.sessions.filter { $0.groupID == current.identity.group?.groupID }.map(\.sessionID)
                for sessionID in sessionIDs {
                    guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }) else {
                        throw ProtocolError.invalidResponse("session disappeared during synchronization")
                    }
                    do {
                        try populateSessionKeys(&current.sessions[index], group: current.identity.group!)
                        let result = try await api.events(for: current.sessions[index], identity: current.identity)
                        for envelope in result.events {
                            let event = try CryptoEngine.decryptEvent(session: current.sessions[index], envelope: envelope)
                            try apply(
                                event, timestamp: envelope.keyTimestamp, createdAt: envelope.createdAt,
                                serverItemID: envelope.itemID, to: &current.sessions[index]
                            )
                            current.sessions[index].cursor = envelope.sequence
                            current.sessions[index].updatedAt = envelope.createdAt
                        }
                        reconcileActiveItems(result.activeItemIDs, in: &current.sessions[index])
                        current.sessions[index].attention = result.attention
                        current.sessions[index].expiresAt = result.expiresAt
                    } catch let error as APIError
                        where (error.status == 404 && error.code == "session_not_found")
                           || (error.status == 410 && error.code == "session_expired") {
                        current.sessions.remove(at: index)
                        try persist(current)
                    } catch let error as APIError where error.status == 403 && error.code == "device_removed" {
                        throw error
                    } catch where Self.isCancellation(error) {
                        throw error
                    } catch {
                        // One session failing to sync must not hide the others behind an alert.
                        sessionSyncErrors[sessionID] = error.localizedDescription
                        continue
                    }
                    sessionSyncErrors[sessionID] = nil
                }
                sessionSyncErrors = sessionSyncErrors.filter { entry in current.sessions.contains { $0.sessionID == entry.key } }
            }
            current = Self.pruningExpiredSessions(from: current, nowMilliseconds: Self.currentTimeMilliseconds())
            try persist(current)
            connectionState = .current; errorMessage = nil
        } catch let error as APIError where error.status == 403 && error.code == "device_removed" {
            do { try await recoverRemovedDevice() } catch { show(error) }
        } catch { show(error) }
    }

    private func approveDeviceRequest(_ link: DeviceRequestLink) async throws {
        var current = try requiredVault()
        guard current.identity.group != nil, pendingDeviceRequest == nil else {
            throw ProtocolError.invalidPairingLink("this device cannot add another device to a group")
        }
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
        if try inheritSessions(&current) { try persist(current) }
        let request = try await api.deviceRequestForApproval(identity: current.identity, requestID: link.requestID)
        let requestHash = CryptoEngine.deviceRequestBindingHash(
            requestID: request.requestID, deviceID: request.deviceID,
            signingPublicKey: request.signingPublicKey, accessHash: request.accessHash,
            encryptionPublicKey: request.encryptionPublicKey, protocolVersion: request.protocolVersion
        )
        guard requestHash == link.requestHash, request.protocolVersion == 4 else {
            throw ProtocolError.crypto("add-to-group link does not authenticate this device request")
        }
        guard let state = groupState, !state.members.contains(where: { $0.deviceID == request.deviceID }) else {
            throw ProtocolError.invalidResponse("device is already in this group")
        }
        let members = state.members.map(transitionMember) + [TransitionMember(
            deviceID: request.deviceID, signingPublicKey: request.signingPublicKey,
            encryptionPublicKey: request.encryptionPublicKey
        )]
        let update = try createMembershipTransition(current: current, members: members, recreated: false)
        let approvalProof = try CryptoEngine.deviceApprovalProof(
            authSecret: link.authSecret, requestID: link.requestID,
            groupID: current.identity.group!.groupID, transitionHash: update.transition.transitionHash
        )
        try await api.approveDeviceRequest(
            identity: current.identity, requestID: link.requestID,
            transition: update.transition, packages: update.packages, approvalProof: approvalProof
        )
        try storeTransitionKey(update, in: &current)
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
        _ = try inheritSessions(&current)
        try persist(current)
    }

    private func stageDeviceAddition(_ link: DeviceRequestLink) throws {
        guard pendingDeviceAddition == nil else {
            throw ProtocolError.invalidPairingLink("another device addition is awaiting approval")
        }
        pendingDeviceAddition = link
        isDeviceAdditionApprovalPending = true
    }

    private func clearPendingDeviceAddition() {
        pendingDeviceAddition = nil
        isDeviceAdditionApprovalPending = false
    }

    private func joinSession(_ pairing: PairingLink) async throws {
        var current = try requiredVault()
        if current.identity.group == nil { try await createSoloGroup(&current) }
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
        if try inheritSessions(&current) { try persist(current) }
        guard !current.sessions.contains(where: { $0.sessionID == pairing.sessionID }),
              let group = current.identity.group,
              let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
            throw ProtocolError.invalidPairingLink("session is already joined or the current group key is unavailable")
        }
        let expiresAt = try await api.join(pairing, identity: current.identity, key: key)
        var record = SessionRecord(
            protocolVersion: pairing.protocolVersion, sessionID: pairing.sessionID, groupID: group.groupID,
            creatorPublicKey: pairing.creatorPublicKey, keys: [:], cursor: 0,
            title: "Session \(pairing.sessionID.prefix(8))", status: "Connected", notifications: [],
            request: nil, requestKeyTimestamp: nil, color: pairing.color,
            updatedAt: Self.currentTimeMilliseconds(), expiresAt: expiresAt
        )
        try populateSessionKeys(&record, group: group)
        current.sessions.append(record)
        try persist(current)
        await enableNotifications()
    }

    private func createSoloGroup(_ current: inout Vault) async throws {
        let groupID = try CryptoEngine.randomID()
        let draft = CryptoEngine.createGroupKey()
        let member = TransitionMember(
            deviceID: current.identity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: current.identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: current.identity)
        )
        let package = try CryptoEngine.createKeyPackage(
            groupID: groupID, key: draft, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let transition = try CryptoEngine.createGroupTransition(
            groupID: groupID, identity: current.identity, groupKey: draft,
            previous: nil, members: [member], packages: [package], recreated: true
        )
        try await api.createGroup(
            groupID: groupID, identity: current.identity, transition: transition, packages: [package]
        )
        let key = GroupKey(
            timestamp: transition.timestamp, publicKey: draft.publicKey,
            privateKey: draft.privateKey, transitionHash: transition.transitionHash
        )
        current.identity.group = DeviceGroup(
            groupID: groupID, keys: [String(transition.timestamp): key],
            rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash
        )
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
    }

    private func pollDeviceRequest(_ current: inout Vault) async throws {
        guard let pending = pendingDeviceRequest else { return }
        switch try await api.deviceRequestStatus(identity: current.identity, requestID: pending.requestID) {
        case .waiting:
            deviceRequestLink = try deviceRequestURL(pending)
        case .expired:
            pendingDeviceRequest = nil; deviceRequestLink = nil
            try await createSoloGroup(&current)
            noticeMessage = "The add-to-group link expired. This device is now used on its own."
        case .approved(let groupID, _, let transitionHash, let approvalProof):
            guard try CryptoEngine.verifyDeviceApprovalProof(
                authSecret: pending.authSecret, requestID: pending.requestID,
                groupID: groupID, transitionHash: transitionHash, proof: approvalProof
            ) else { throw ProtocolError.crypto("device approval proof is invalid") }
            pendingDeviceRequest = nil
            current.identity.group = DeviceGroup(
                groupID: groupID, keys: [:], pendingTransitionHash: transitionHash
            )
            deviceRequestLink = nil
            try await synchronizeGroup(&current)
            try await ensureExactGroupKey(&current)
            await enableNotifications()
        }
    }

    private func synchronizeGroup(_ current: inout Vault) async throws {
        guard var group = current.identity.group else { return }
        let state = try await api.groupState(identity: current.identity)
        guard let trustedHash = group.headTransitionHash ?? group.pendingTransitionHash else {
            throw ProtocolError.crypto("device group has no authenticated transition anchor")
        }
        let head = try CryptoEngine.validateGroupTransitions(
            groupID: state.groupID, transitions: state.keys, trustedHash: trustedHash
        )
        guard sameTransitionMembers(head.members, state.members.map(transitionMember)) else {
            throw ProtocolError.crypto("relay changed the active group member set")
        }
        for package in state.packages {
            guard let timestamp = package.timestamp,
                  let record = state.keys.first(where: { $0.timestamp == timestamp }) else {
                throw ProtocolError.crypto("key package refers to an unknown key")
            }
            try CryptoEngine.verifyKeyPackageDigest(package, transition: record)
            if let local = group.keys[String(timestamp)] {
                guard local.publicKey == record.publicKey, local.transitionHash == record.transitionHash else {
                    throw ProtocolError.crypto("stored key conflicts with server metadata")
                }
            } else {
                group.keys[String(timestamp)] = try CryptoEngine.openKeyPackage(
                    identity: current.identity, groupID: group.groupID, record: record, package: package
                )
            }
        }
        if group.rootTransitionHash == nil { group.rootTransitionHash = state.keys.first?.transitionHash }
        group.headTransitionHash = head.transitionHash
        group.pendingTransitionHash = nil
        current.identity.group = group
        groupState = state
        groupDevices = state.members
        currentKeyTimestamp = GroupKeyPolicy.selectUsableKey(state)?.timestamp
        try persist(current)
    }

    private func ensureExactGroupKey(_ current: inout Vault) async throws {
        guard let state = groupState, GroupKeyPolicy.latestKeyMatchesMembers(state) else {
            throw ProtocolError.crypto("device group key does not match its authenticated members")
        }
        guard GroupKeyPolicy.needsRecreation(state) else { return }
        let update = try createMembershipTransition(
            current: current, members: state.members.map(transitionMember), recreated: true
        )
        do {
            let acceptedHash = try await api.registerGroupKey(
                identity: current.identity, transition: update.transition, packages: update.packages
            )
            guard acceptedHash == update.transition.transitionHash else {
                throw ProtocolError.crypto("accepted group transition hash changed")
            }
            try storeTransitionKey(update, in: &current)
        } catch let error as APIError
            where error.code == "group_transition_changed" || error.code == "key_timestamp_conflict" {
            try await synchronizeGroup(&current)
            return
        }
        try await synchronizeGroup(&current)
    }

    private func currentGroupKey(state: DeviceGroupStateResult, group: DeviceGroup) throws -> GroupKey? {
        guard let record = GroupKeyPolicy.selectUsableKey(state) else { return nil }
        guard let key = group.keys[String(record.timestamp)], key.publicKey == record.publicKey else {
            throw ProtocolError.crypto("current group private key is unavailable")
        }
        guard key.transitionHash == record.transitionHash else {
            throw ProtocolError.crypto("current group key transition is not authenticated")
        }
        return key
    }

    private func inheritSessions(_ current: inout Vault) throws -> Bool {
        guard let group = current.identity.group, let state = groupState else { return false }
        let previousSessions = current.sessions
        let authenticated = try CryptoEngine.authenticatedInheritedSessions(
            state.sessions, groupID: group.groupID, transitions: state.keys
        )
        var authenticatedByID: [String: GroupSessionResult] = [:]
        var duplicateIDs = Set<String>()
        for remote in authenticated {
            if authenticatedByID.updateValue(remote, forKey: remote.sessionID) != nil {
                duplicateIDs.insert(remote.sessionID)
            }
        }
        for sessionID in duplicateIDs { authenticatedByID.removeValue(forKey: sessionID) }
        var nextSessions = current.sessions.filter {
            guard $0.protocolVersion == 4 && $0.groupID == group.groupID else { return true }
            guard let remote = authenticatedByID[$0.sessionID] else { return false }
            return remote.protocolVersion == $0.protocolVersion && remote.groupID == $0.groupID
                && remote.creatorPublicKey == $0.creatorPublicKey
        }
        var localSessionIDs = Set(nextSessions.map(\.sessionID))
        for remote in authenticated
            where authenticatedByID[remote.sessionID] != nil && !localSessionIDs.contains(remote.sessionID) {
            var record = SessionRecord(
                protocolVersion: remote.protocolVersion, sessionID: remote.sessionID, groupID: group.groupID,
                creatorPublicKey: remote.creatorPublicKey, keys: [:], cursor: 0,
                title: "Session \(remote.sessionID.prefix(8))", status: "Connected", notifications: [],
                request: nil, requestKeyTimestamp: nil, color: nil,
                updatedAt: Self.currentTimeMilliseconds(), expiresAt: remote.expiresAt
            )
            do {
                try populateSessionKeys(&record, group: group)
                nextSessions.append(record)
                localSessionIDs.insert(remote.sessionID)
            } catch {
                // A single relay-controlled session must not block retirement of
                // other stale sessions or persistence of the authenticated set.
                continue
            }
        }
        current.sessions = nextSessions
        return current.sessions != previousSessions
    }

    private func populateSessionKeys(_ session: inout SessionRecord, group: DeviceGroup) throws {
        for key in group.keys.values where session.keys[String(key.timestamp)] == nil {
            session.keys[String(key.timestamp)] = try CryptoEngine.deriveSessionKey(
                key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID,
                groupID: group.groupID, protocolVersion: session.protocolVersion
            )
        }
    }

    private func apply(
        _ event: SessionEvent,
        timestamp: Int64,
        createdAt: Int64,
        serverItemID: String?,
        to session: inout SessionRecord
    ) throws {
        switch event {
        case .notification(let id, let title, let message, let color):
            if let serverItemID, serverItemID != id {
                throw ProtocolError.invalidResponse("notification ID does not match its server item ID")
            }
            session.title = title
            session.notifications.append(
                SessionNotification(id: id, message: message, createdAt: createdAt, serverItemID: serverItemID)
            )
            session.color = color
        case .status(let title, let value, let color):
            session.title = title; session.status = value; session.color = color
        case .request(let title, let value, let color):
            if let serverItemID, serverItemID != value.id {
                throw ProtocolError.invalidResponse("request ID does not match its server item ID")
            }
            session.title = title
            session.request = SessionRequest(
                id: value.id, prompt: value.prompt, options: value.options,
                createdAt: createdAt, serverItemID: serverItemID
            )
            session.requestKeyTimestamp = timestamp
            session.color = color
        case .closeRequest(let title, let requestID, let color):
            session.title = title; session.color = color
            if session.request?.id == requestID { session.request = nil; session.requestKeyTimestamp = nil }
        case .color(let title, let value):
            session.title = title; session.color = value
        }
    }

    private func reconcileActiveItems(_ activeItemIDs: [String], in session: inout SessionRecord) {
        let active = Set(activeItemIDs)
        session.notifications.removeAll { notification in
            notification.serverItemID.map { !active.contains($0) } ?? false
        }
        if let itemID = session.request?.serverItemID, !active.contains(itemID) {
            session.request = nil
            session.requestKeyTimestamp = nil
        }
    }

    private func recoverRemovedDevice() async throws {
        var current = try requiredVault()
        guard let groupID = current.identity.group?.groupID else { return }
        current = Self.detachingFromDeviceGroup(current, groupID: groupID)
        clearPublishedGroupState()
        try await createSoloGroup(&current)
        try persist(current)
        noticeMessage = "This device was removed from its group. It is now used on its own."
        connectionState = .current
    }

    private func registerPushToken(_ token: String, environment: PushEnvironment) async {
        do { try await api.registerPushToken(token, environment: environment, identity: try requiredVault().identity) }
        catch { show(error) }
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

    private func transitionMember(_ device: GroupDevice) -> TransitionMember {
        TransitionMember(
            deviceID: device.deviceID, signingPublicKey: device.signingPublicKey,
            encryptionPublicKey: device.encryptionPublicKey
        )
    }

    private func sameTransitionMembers(_ left: [TransitionMember], _ right: [TransitionMember]) -> Bool {
        let normalize: ([TransitionMember]) -> [String] = { members in
            members.sorted { $0.deviceID.utf8.lexicographicallyPrecedes($1.deviceID.utf8) }
                .map { "\($0.deviceID)\n\($0.signingPublicKey)\n\($0.encryptionPublicKey)" }
        }
        return normalize(left) == normalize(right)
    }

    private func createMembershipTransition(
        current: Vault, members: [TransitionMember], recreated: Bool
    ) throws -> (key: GroupKey, packages: [KeyPackage], transition: GroupKeyRecord) {
        guard let group = current.identity.group, let state = groupState, let previous = state.keys.last,
              previous.transitionHash == group.headTransitionHash else {
            throw ProtocolError.crypto("device group transition head is not synchronized")
        }
        let draft = CryptoEngine.createGroupKey()
        let packages = try members.map {
            try CryptoEngine.createKeyPackage(
                groupID: group.groupID, key: draft, deviceID: $0.deviceID,
                encryptionPublicKey: $0.encryptionPublicKey
            )
        }
        let transition = try CryptoEngine.createGroupTransition(
            groupID: group.groupID, identity: current.identity, groupKey: draft,
            previous: previous, members: members, packages: packages, recreated: recreated
        )
        return (draft, packages, transition)
    }

    private func createSelfRemovalTransition(
        current: Vault, members: [TransitionMember]
    ) throws -> (key: GroupKey, packages: [KeyPackage], transition: GroupKeyRecord) {
        guard let group = current.identity.group, let state = groupState, let previous = state.keys.last,
              previous.transitionHash == group.headTransitionHash,
              let currentKey = group.keys[String(previous.timestamp)],
              currentKey.publicKey == previous.publicKey else {
            throw ProtocolError.crypto("device group transition head is not synchronized")
        }
        let packages = try members.map {
            try CryptoEngine.createKeyPackage(
                groupID: group.groupID, key: currentKey, deviceID: $0.deviceID,
                encryptionPublicKey: $0.encryptionPublicKey
            )
        }
        let transition = try CryptoEngine.createGroupTransition(
            groupID: group.groupID, identity: current.identity, groupKey: currentKey,
            previous: previous, members: members, packages: packages, recreated: false
        )
        return (currentKey, packages, transition)
    }

    private func storeTransitionKey(
        _ update: (key: GroupKey, packages: [KeyPackage], transition: GroupKeyRecord),
        in current: inout Vault
    ) throws {
        guard var group = current.identity.group else { throw ProtocolError.crypto("device group is unavailable") }
        group.keys[String(update.transition.timestamp)] = GroupKey(
            timestamp: update.transition.timestamp, publicKey: update.key.publicKey,
            privateKey: update.key.privateKey, transitionHash: update.transition.transitionHash
        )
        group.headTransitionHash = update.transition.transitionHash
        current.identity.group = group
        try persist(current)
    }

    private func requiredGroupState() throws -> DeviceGroupStateResult {
        guard let groupState else { throw ProtocolError.crypto("group state is unavailable") }
        return groupState
    }

    private func persist(_ value: Vault) throws {
        if !isSessionHistoryUITest { try keychain.save(value) }
        vault = value
        publish(value)
    }

    private func publish(_ value: Vault) {
        sessions = value.sessions.sorted { ($0.updatedAt ?? 0) > ($1.updatedAt ?? 0) }
        hasDeviceGroup = value.identity.group != nil
        deviceID = value.identity.deviceID
    }

    private func clearPublishedGroupState() {
        groupState = nil; groupDevices = []; currentKeyTimestamp = nil
        pendingDeviceRequest = nil; deviceRequestLink = nil
        clearPendingDeviceAddition()
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
        guard !Self.isCancellation(error) else { return }
        errorMessage = error.localizedDescription; connectionState = .failed
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
        let member = TransitionMember(
            deviceID: identity.deviceID,
            signingPublicKey: try CryptoEngine.signingPublicKey(for: identity),
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: identity)
        )
        let draft = CryptoEngine.createGroupKey()
        let package = try CryptoEngine.createKeyPackage(
            groupID: groupID, key: draft, deviceID: member.deviceID,
            encryptionPublicKey: member.encryptionPublicKey
        )
        let transition = try CryptoEngine.createGroupTransition(
            groupID: groupID, identity: identity, groupKey: draft, previous: nil,
            members: [member], packages: [package], recreated: true, now: 10
        )
        let key = GroupKey(
            timestamp: transition.timestamp, publicKey: draft.publicKey,
            privateKey: draft.privateKey, transitionHash: transition.transitionHash
        )
        identity.group = DeviceGroup(
            groupID: groupID, keys: [String(key.timestamp): key],
            rootTransitionHash: transition.transitionHash, headTransitionHash: transition.transitionHash
        )
        let descriptor = try CryptoEngine.createSessionDescriptor(
            identity: identity, key: key, sessionID: "authenticated-v4-session",
            groupID: groupID, creatorPublicKey: draft.publicKey
        )
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
        groupState = DeviceGroupStateResult(
            groupID: groupID,
            members: [GroupDevice(
                deviceID: member.deviceID, encryptionPublicKey: member.encryptionPublicKey,
                signingPublicKey: member.signingPublicKey, addedAt: 0
            )],
            keys: [transition], packages: [], sessions: [legacy, signed]
        )
        let attackerKey = CryptoEngine.createGroupKey()
        let stale = SessionRecord(
            protocolVersion: 4, sessionID: signed.sessionID, groupID: groupID,
            creatorPublicKey: attackerKey.publicKey, keys: [:], cursor: 0,
            title: "Tampered local session", status: "Unsafe", notifications: [],
            request: nil, requestKeyTimestamp: nil, color: nil,
            updatedAt: Self.currentTimeMilliseconds(), expiresAt: signed.expiresAt
        )
        var current = Vault(version: 4, identity: identity, sessions: [stale])
        guard try inheritSessions(&current), current.sessions.count == 1,
              current.sessions[0].creatorPublicKey == signed.creatorPublicKey else {
            throw ProtocolError.crypto("authenticated session did not replace the stale local creator key")
        }
        current.sessions[0].title = "Authenticated v4 session"
        current.sessions[0].status = "Connected securely"
        current.sessions[0].color = "#d9f2d0"
        vault = current
        publish(current)
        groupDevices = [GroupDevice(
            deviceID: member.deviceID, encryptionPublicKey: member.encryptionPublicKey,
            signingPublicKey: member.signingPublicKey, addedAt: 0
        )]
        connectionState = .current
        isReady = true
        hasFinishedStarting = true
    }

    private func startSessionHistoryUITest() {
        let now = Self.currentTimeMilliseconds()
        let session = SessionRecord(
            protocolVersion: 4, sessionID: "ui-test-session", groupID: "ui-test-group",
            creatorPublicKey: "unused", keys: ["42": Data(repeating: 7, count: 32)], cursor: 3,
            title: "UI improvement test", status: "Working",
            notifications: [
                SessionNotification(
                    id: "notice-1", message: "First accumulated notice",
                    createdAt: now - 2_000
                ),
                SessionNotification(
                    id: "notice-2", message: "Second accumulated notice",
                    createdAt: now - 20 * 60_000
                ),
            ],
            request: SessionRequest(
                id: "request-1", prompt: "Continue the meeting?",
                options: [SessionChoice(id: "yes", label: "Yes"), SessionChoice(id: "no", label: "No")],
                createdAt: now - 30_000
            ),
            requestKeyTimestamp: 42, color: "#d9f2d0", updatedAt: now - 20 * 60_000,
            expiresAt: now + 86_400_000
        )
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
        let identity = DeviceIdentity(
            deviceID: "ui-test-device", accessToken: "unused",
            encryptionPrivateKey: Data(repeating: 1, count: 32),
            signingPrivateKey: Data(repeating: 2, count: 32),
            group: DeviceGroup(groupID: "ui-test-group", keys: [:])
        )
        let current = Vault(version: 4, identity: identity, sessions: uiTestSessions)
        vault = current
        publish(current)
        if ProcessInfo.processInfo.arguments.contains("-ui-test-session-sync-error") {
            sessionSyncErrors[session.sessionID] = "Invalid server response: object fields do not match the protocol"
        }
        groupDevices = [GroupDevice(deviceID: identity.deviceID, encryptionPublicKey: "unused", addedAt: 0)]
        connectionState = .current
        isReady = true
        hasFinishedStarting = true
    }
#endif

    nonisolated static func pruningExpiredSessions(from vault: Vault, nowMilliseconds: Int64) -> Vault {
        var result = vault; result.sessions.removeAll { $0.expiresAt <= nowMilliseconds }; return result
    }

    nonisolated static func detachingFromDeviceGroup(_ vault: Vault, groupID: String) -> Vault {
        var result = vault
        result.identity.group = nil
        result.sessions.removeAll {
            ($0.protocolVersion == 3 || $0.protocolVersion == 4) && $0.groupID == groupID
        }
        return result
    }

    nonisolated private static func currentTimeMilliseconds() -> Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }
}
