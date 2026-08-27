import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var sessions: [SessionRecord] = []
    @Published private(set) var groupDevices: [GroupDevice] = []
    @Published private(set) var currentKeyTimestamp: Int64?
    @Published private(set) var hasDeviceGroup = false
    @Published private(set) var deviceID: String?
    @Published private(set) var deviceRequestLink: String?
    @Published private(set) var connectionState: ConnectionState = .preparing
    @Published private(set) var isReady = false
    @Published private(set) var startupErrorMessage: String?
    @Published private(set) var canResetLocalData = false
    @Published var errorMessage: String?
    @Published var noticeMessage: String?

    private let keychain = KeychainVault()
    private let api = APIClient()
    private var vault: Vault?
    private var groupState: DeviceGroupStateResult?
    private var pendingDeviceRequest: DeviceRequestRecord?
    private var pendingUniversalLink: URL?
    private var hasFinishedStarting = false
    private var isSyncing = false

    var isAwaitingDeviceApproval: Bool { pendingDeviceRequest != nil }
    var deviceCount: Int { max(1, groupDevices.count) }
    var isSharingAcrossDevices: Bool { groupDevices.count > 1 }
    var deviceRequestWouldDiscardCurrentState: Bool { isSharingAcrossDevices || !sessions.isEmpty }

    func start() async {
        guard !isReady else { return }
        do {
            PushCoordinator.shared.onToken = { [weak self] token, environment in
                guard let self else { return }
                Task { await self.registerPushToken(token, environment: environment) }
            }
            PushCoordinator.shared.onFailure = { [weak self] error in self?.show(error) }
            let loaded = try keychain.load()
            var current: Vault
            if let loaded {
                current = Self.pruningExpiredSessions(from: loaded, nowMilliseconds: Self.currentTimeMilliseconds())
            } else {
                var identity = try CryptoEngine.createIdentity()
                identity.deviceID = try await api.registerDevice(identity: identity)
                current = Vault(version: 3, identity: identity, sessions: [])
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
        while !Task.isCancelled {
            await sync()
            do { try await Task.sleep(for: .seconds(2)) }
            catch is CancellationError { return }
            catch { show(error); return }
        }
    }

    func join(link: String) async -> Bool {
        do {
            let value = link.trimmingCharacters(in: .whitespacesAndNewlines)
            if URLComponents(string: value)?.path == "/device" {
                try await approveDeviceRequest(DeviceRequestLink(value))
            } else {
                try await joinSession(PairingLink(value))
            }
            errorMessage = nil
            await sync()
            return true
        } catch { show(error); return false }
    }

    func openUniversalLink(_ url: URL) async {
        guard !hasFinishedStarting else {
            _ = await join(link: url.absoluteString)
            return
        }
        pendingUniversalLink = url
    }

    func createDeviceRequest(discardingCurrentState: Bool = false) async {
        do {
            var current = try requiredVault()
            if let pendingDeviceRequest {
                deviceRequestLink = try deviceRequestURL(pendingDeviceRequest)
                return
            }
            try await synchronizeGroup(&current)
            if deviceRequestWouldDiscardCurrentState && !discardingCurrentState {
                throw ProtocolError.invalidResponse("confirm removing this device from its current group and deleting its saved sessions")
            }
            if let groupID = current.identity.group?.groupID {
                try await api.removeDevice(identity: current.identity, deviceID: current.identity.deviceID)
                current = Self.detachingFromDeviceGroup(current, groupID: groupID)
                clearPublishedGroupState()
            }
            let requestID = try CryptoEngine.randomID()
            let created = try await api.createDeviceRequest(identity: current.identity, requestID: requestID)
            pendingDeviceRequest = created
            try persist(current)
            deviceRequestLink = try deviceRequestURL(created)
            errorMessage = nil
        } catch { show(error) }
    }

    func removeDevice(_ deviceID: String) async {
        do {
            var current = try requiredVault()
            try await api.removeDevice(identity: current.identity, deviceID: deviceID)
            try await synchronizeGroup(&current)
            try await ensureExactGroupKey(&current)
            try persist(current)
        } catch { show(error) }
    }

    func leaveDeviceGroup() async {
        do {
            var current = try requiredVault()
            guard groupDevices.count > 1, let groupID = current.identity.group?.groupID else {
                throw ProtocolError.invalidResponse("this device cannot be removed from a group with no other devices")
            }
            try await api.removeDevice(identity: current.identity, deviceID: current.identity.deviceID)
            current = Self.detachingFromDeviceGroup(current, groupID: groupID)
            clearPublishedGroupState()
            try await createSoloGroup(&current)
            try persist(current)
        } catch { show(error) }
    }

    func respond(sessionID: String, optionID: String) async {
        do {
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let request = current.sessions[index].request,
                  let timestamp = current.sessions[index].requestKeyTimestamp else {
                throw ProtocolError.invalidResponse("request is no longer available")
            }
            let responseID = try CryptoEngine.randomID()
            let payload = try CryptoEngine.encryptResponse(
                session: current.sessions[index], timestamp: timestamp, responseID: responseID,
                requestID: request.id, optionID: optionID, createdAt: ISO8601DateFormatter().string(from: Date())
            )
            current.sessions[index].expiresAt = try await api.postResponse(
                session: current.sessions[index], identity: current.identity, timestamp: timestamp,
                responseID: responseID, payload: payload
            )
            current.sessions[index].request = nil
            current.sessions[index].status = "Response sent"
            try persist(current)
        } catch { show(error) }
    }

    func sendFeedback(sessionID: String, message: String) async -> Bool {
        do {
            let text = message.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty, text.count <= 20_000 else {
                throw ProtocolError.invalidResponse("message must contain between 1 and 20000 characters")
            }
            var current = try requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let group = current.identity.group,
                  let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
                throw ProtocolError.invalidResponse("session feedback key is unavailable")
            }
            try populateSessionKeys(&current.sessions[index], group: group)
            let responseID = try CryptoEngine.randomID()
            let payload = try CryptoEngine.encryptFeedback(
                session: current.sessions[index], timestamp: key.timestamp, responseID: responseID,
                message: text, createdAt: RFC3339.string(from: Date())
            )
            current.sessions[index].expiresAt = try await api.postResponse(
                session: current.sessions[index], identity: current.identity, timestamp: key.timestamp,
                responseID: responseID, payload: payload
            )
            try persist(current)
            return true
        } catch {
            show(error)
            return false
        }
    }

    func enableNotifications() async {
        do { _ = try await PushCoordinator.shared.enable() } catch { show(error) }
    }

    func resumeNotifications() async { await PushCoordinator.shared.resumeIfAuthorized() }
    func dismissError() { errorMessage = nil }
    func dismissNotice() { noticeMessage = nil }

    private func openPendingUniversalLink() async {
        guard let url = pendingUniversalLink else { return }
        pendingUniversalLink = nil
        _ = await join(link: url.absoluteString)
    }

    func resetLocalData() async {
        guard canResetLocalData else { return }
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
        guard isReady, !isSyncing else { return }
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
                try inheritSessions(&current)
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
                            apply(event, timestamp: envelope.keyTimestamp, to: &current.sessions[index])
                            current.sessions[index].cursor = envelope.sequence
                            current.sessions[index].updatedAt = envelope.createdAt
                        }
                        current.sessions[index].expiresAt = result.expiresAt
                    } catch let error as APIError
                        where (error.status == 404 && error.code == "session_not_found")
                           || (error.status == 410 && error.code == "session_expired") {
                        current.sessions.remove(at: index)
                        try persist(current)
                    }
                }
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
        try await api.approveDeviceRequest(identity: current.identity, requestID: link.requestID)
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
        try persist(current)
    }

    private func joinSession(_ pairing: PairingLink) async throws {
        var current = try requiredVault()
        if current.identity.group == nil { try await createSoloGroup(&current) }
        try await synchronizeGroup(&current)
        try await ensureExactGroupKey(&current)
        guard !current.sessions.contains(where: { $0.sessionID == pairing.sessionID }),
              let group = current.identity.group,
              let key = try currentGroupKey(state: requiredGroupState(), group: group) else {
            throw ProtocolError.invalidPairingLink("session is already joined or the current group key is unavailable")
        }
        let expiresAt = try await api.join(pairing, identity: current.identity, key: key)
        var record = SessionRecord(
            protocolVersion: 3, sessionID: pairing.sessionID, groupID: group.groupID,
            creatorPublicKey: pairing.creatorPublicKey, keys: [:], cursor: 0,
            title: "Session \(pairing.sessionID.prefix(8))", status: "Connected", notification: "",
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
        try await api.createGroup(groupID: groupID, identity: current.identity)
        current.identity.group = DeviceGroup(groupID: groupID, keys: [:])
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
        case .approved(let groupID, _):
            pendingDeviceRequest = nil
            current.identity.group = DeviceGroup(groupID: groupID, keys: [:])
            deviceRequestLink = nil
            try await synchronizeGroup(&current)
            try await ensureExactGroupKey(&current)
            await enableNotifications()
        }
    }

    private func synchronizeGroup(_ current: inout Vault) async throws {
        guard var group = current.identity.group else { return }
        let state = try await api.groupState(identity: current.identity)
        for package in state.packages {
            guard let timestamp = package.timestamp,
                  let record = state.keys.first(where: { $0.timestamp == timestamp }) else {
                throw ProtocolError.crypto("key package refers to an unknown key")
            }
            if let local = group.keys[String(timestamp)] {
                guard local.publicKey == record.publicKey else { throw ProtocolError.crypto("stored key conflicts with server metadata") }
            } else {
                group.keys[String(timestamp)] = try CryptoEngine.openKeyPackage(
                    identity: current.identity, groupID: group.groupID, record: record, package: package
                )
            }
        }
        current.identity.group = group
        groupState = state
        groupDevices = state.members
        currentKeyTimestamp = GroupKeyPolicy.selectUsableKey(state)?.timestamp
        try persist(current)
    }

    private func ensureExactGroupKey(_ current: inout Vault) async throws {
        guard let state = groupState, var group = current.identity.group else { throw ProtocolError.crypto("group state is unavailable") }
        if GroupKeyPolicy.latestKeyMatchesMembers(state) { return }
        let draft = CryptoEngine.createGroupKey()
        let timestamp: Int64
        do {
            timestamp = try await api.registerGroupKey(
                identity: current.identity, key: draft,
                recreated: GroupKeyPolicy.nextKeyIsRecreated(state), members: state.members
            )
        } catch let error as APIError where error.code == "member_set_changed" || error.code == "key_timestamp_conflict" {
            try await synchronizeGroup(&current)
            return
        }
        group.keys[String(timestamp)] = GroupKey(timestamp: timestamp, publicKey: draft.publicKey, privateKey: draft.privateKey)
        current.identity.group = group
        try persist(current)
        try await synchronizeGroup(&current)
    }

    private func currentGroupKey(state: DeviceGroupStateResult, group: DeviceGroup) throws -> GroupKey? {
        guard let record = GroupKeyPolicy.selectUsableKey(state) else { return nil }
        guard let key = group.keys[String(record.timestamp)], key.publicKey == record.publicKey else {
            throw ProtocolError.crypto("current group private key is unavailable")
        }
        return key
    }

    private func inheritSessions(_ current: inout Vault) throws {
        guard let group = current.identity.group, let state = groupState else { return }
        for remote in state.sessions where !current.sessions.contains(where: { $0.sessionID == remote.sessionID }) {
            var record = SessionRecord(
                protocolVersion: 3, sessionID: remote.sessionID, groupID: group.groupID,
                creatorPublicKey: remote.creatorPublicKey, keys: [:], cursor: 0,
                title: "Session \(remote.sessionID.prefix(8))", status: "Connected", notification: "",
                request: nil, requestKeyTimestamp: nil, color: nil,
                updatedAt: Self.currentTimeMilliseconds(), expiresAt: remote.expiresAt
            )
            try populateSessionKeys(&record, group: group)
            current.sessions.append(record)
        }
    }

    private func populateSessionKeys(_ session: inout SessionRecord, group: DeviceGroup) throws {
        for key in group.keys.values where session.keys[String(key.timestamp)] == nil {
            session.keys[String(key.timestamp)] = try CryptoEngine.deriveSessionKey(
                key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID, groupID: group.groupID
            )
        }
    }

    private func apply(_ event: SessionEvent, timestamp: Int64, to session: inout SessionRecord) {
        switch event {
        case .notification(let title, let message, let color):
            session.title = title; session.notification = message; session.color = color
        case .status(let title, let value, let color):
            session.title = title; session.status = value; session.color = color
        case .request(let title, let value, let color):
            session.title = title; session.request = value; session.requestKeyTimestamp = timestamp; session.color = color
        case .closeRequest(let title, let requestID, let color):
            session.title = title; session.color = color
            if session.request?.id == requestID { session.request = nil; session.requestKeyTimestamp = nil }
        case .color(let title, let value):
            session.title = title; session.color = value
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
            URLQueryItem(name: "v", value: "2"), URLQueryItem(name: "r", value: request.requestID),
        ]
        var result = URLComponents(string: "https://notify.guru/device")!
        result.percentEncodedFragment = fragment.percentEncodedQuery
        guard let value = result.url?.absoluteString else { throw ProtocolError.invalidResponse("could not create the link for adding this device") }
        return value
    }

    private func requiredGroupState() throws -> DeviceGroupStateResult {
        guard let groupState else { throw ProtocolError.crypto("group state is unavailable") }
        return groupState
    }

    private func persist(_ value: Vault) throws {
        try keychain.save(value); vault = value; publish(value)
    }

    private func publish(_ value: Vault) {
        sessions = value.sessions.sorted { ($0.updatedAt ?? 0) > ($1.updatedAt ?? 0) }
        hasDeviceGroup = value.identity.group != nil
        deviceID = value.identity.deviceID
    }

    private func clearPublishedGroupState() {
        groupState = nil; groupDevices = []; currentKeyTimestamp = nil
        pendingDeviceRequest = nil; deviceRequestLink = nil
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
        guard !(error is CancellationError), (error as? URLError)?.code != .cancelled else { return }
        errorMessage = error.localizedDescription; connectionState = .failed
    }

    nonisolated static func pruningExpiredSessions(from vault: Vault, nowMilliseconds: Int64) -> Vault {
        var result = vault; result.sessions.removeAll { $0.expiresAt <= nowMilliseconds }; return result
    }

    nonisolated static func detachingFromDeviceGroup(_ vault: Vault, groupID: String) -> Vault {
        var result = vault
        result.identity.group = nil
        result.sessions.removeAll { $0.protocolVersion == 3 && $0.groupID == groupID }
        return result
    }

    nonisolated private static func currentTimeMilliseconds() -> Int64 { Int64(Date().timeIntervalSince1970 * 1_000) }
}
