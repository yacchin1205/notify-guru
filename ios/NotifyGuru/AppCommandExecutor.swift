import Foundation

protocol AppCommandStorage {
    func save(_ vault: Vault) throws
}

extension KeychainVault: AppCommandStorage {}

struct SessionSynchronizationError: LocalizedError {
    let sessionID: String
    let underlyingError: Error

    var errorDescription: String? {
        "Session \(sessionID): \(underlyingError.localizedDescription)"
    }
}

@MainActor
/// This class must never retain mutable application state. notify.guru rotates
/// and redistributes keys associated with sessions as it operates, so concurrent
/// operations using different state snapshots can destroy the authenticated state.
/// Every application operation must be serialized through the command queue.
final class AppCommandExecutor {
    private let api: APIClient
    private let storage: any AppCommandStorage

    init(
        api: APIClient = APIClient(), storage: any AppCommandStorage = KeychainVault()
    ) {
        self.api = api
        self.storage = storage
    }

    func execute(
        _ command: AppCommand,
        state initialState: AppCommandState
    ) async throws -> AppCommandResult {
        switch command {
        case .synchronize:
            return try await synchronize(state: initialState)
        case .joinSession(let groupID, let pairingURL):
            let nextState = try await joinSession(
                groupID: groupID, pairingURL: pairingURL, state: initialState
            )
            return try await synchronize(state: nextState)
        case .approveDeviceAddition(let groupID, let requestURL):
            let nextState = try await approveDeviceAddition(
                groupID: groupID, requestURL: requestURL, state: initialState
            )
            return try await synchronize(state: nextState)
        case .prepareDeviceGroupJoin(let groupID, let discardSavedSessions):
            let nextState = try await prepareDeviceGroupJoin(
                groupID: groupID, discardSavedSessions: discardSavedSessions,
                state: initialState
            )
            return AppCommandResult(nextState: nextState, changes: [])
        case .removeDevice(let groupID, let deviceID):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            let nextState = try await removeDevice(
                groupID: groupID, deviceID: deviceID,
                state: initialState, groupState: groupState
            )
            return AppCommandResult(nextState: nextState, changes: [])
        case .leaveDeviceGroup(let groupID):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            let nextState = try await leaveDeviceGroup(
                groupID: groupID, state: initialState, groupState: groupState
            )
            return AppCommandResult(nextState: nextState, changes: [])
        case .respond(let sessionID, let requestID, let optionID):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            let vault = try await respond(
                sessionID: sessionID, requestID: requestID, optionID: optionID,
                vault: initialState.vault, groupState: groupState
            )
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: vault, groupState: groupState,
                    pendingDeviceRequest: initialState.pendingDeviceRequest
                ),
                changes: []
            )
        case .dismissRequest(let sessionID, let requestID):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            let vault = try await dismissRequest(
                sessionID: sessionID, requestID: requestID,
                vault: initialState.vault, groupState: groupState
            )
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: vault, groupState: groupState,
                    pendingDeviceRequest: initialState.pendingDeviceRequest
                ),
                changes: []
            )
        case .dismissNotification(let sessionID, let notificationID):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            let vault = try await dismissNotification(
                sessionID: sessionID, notificationID: notificationID,
                vault: initialState.vault, groupState: groupState
            )
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: vault, groupState: groupState,
                    pendingDeviceRequest: initialState.pendingDeviceRequest
                ),
                changes: []
            )
        case .sendFeedback(let sessionID, let message, let photos):
            guard let groupState = initialState.groupState else {
                throw ProtocolError.crypto("group state is unavailable")
            }
            try await sendFeedback(
                sessionID: sessionID, message: message, photos: photos,
                vault: initialState.vault, groupState: groupState
            )
            return AppCommandResult(nextState: initialState, changes: [])
        case .setAttention(let sessionID, let enabled):
            let vault = try await setAttention(
                sessionID: sessionID, enabled: enabled, vault: initialState.vault
            )
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: vault, groupState: initialState.groupState,
                    pendingDeviceRequest: initialState.pendingDeviceRequest
                ),
                changes: []
            )
        case .registerPushToken(let token, let environment):
            try await api.registerPushToken(
                token, environment: environment, identity: initialState.vault.identity
            )
            return AppCommandResult(nextState: initialState, changes: [])
        }
    }

    func initialize(
        _ loaded: Vault?, groupState initialGroupState: DeviceGroupStateResult?
    ) async throws -> AppCommandState {
        var current: Vault
        if let loaded {
            current = loaded
            current.sessions.removeAll { $0.expiresAt <= Self.currentTimeMilliseconds() }
        } else {
            var identity = try CryptoEngine.createIdentity()
            identity.deviceID = try await api.registerDevice(identity: identity)
            current = Vault(version: 4, identity: identity, sessions: [])
        }
        let groupState: DeviceGroupStateResult?
        if current.identity.group == nil {
            groupState = try await createSoloGroup(&current)
        } else {
            groupState = initialGroupState
        }
        try persist(current)
        return AppCommandState(
            vault: current, groupState: groupState, pendingDeviceRequest: nil
        )
    }

    private func requireGroup(_ groupID: String, vault: Vault) throws {
        guard vault.identity.group?.groupID == groupID else {
            throw ProtocolError.invalidResponse("the command's device group is no longer available")
        }
    }

    private func joinSession(
        groupID: String,
        pairingURL: String,
        state: AppCommandState
    ) async throws -> AppCommandState {
        try requireGroup(groupID, vault: state.vault)
        let pairing = try PairingLink(pairingURL)
        var current = state.vault
        var groupState = try await synchronizeGroup(&current)
        groupState = try await ensureExactGroupKey(&current, groupState: groupState)
        if try Self.inheritSessions(&current, groupState: groupState) { try persist(current) }
        guard let group = current.identity.group else {
            throw ProtocolError.invalidPairingLink("device group is unavailable")
        }
        let existingIndex = current.sessions.firstIndex(where: { $0.sessionID == pairing.sessionID })
        if let existingIndex {
            let existing = current.sessions[existingIndex]
            guard existing.protocolVersion == pairing.protocolVersion,
                  existing.groupID == group.groupID,
                  existing.creatorPublicKey == pairing.creatorPublicKey else {
                throw ProtocolError.invalidPairingLink("session identifier conflicts with the joined session")
            }
        }
        guard let key = try Self.currentGroupKey(state: groupState, group: group) else {
            throw ProtocolError.invalidPairingLink("the current group key is unavailable")
        }
        let expiresAt: Int64
        do {
            expiresAt = try await api.join(pairing, identity: current.identity, key: key)
        } catch let error as APIError where existingIndex != nil && error.status == 409 && error.code == "group_joined" {
            return AppCommandState(
                vault: current, groupState: groupState,
                pendingDeviceRequest: state.pendingDeviceRequest
            )
        }
        if let existingIndex {
            current.sessions[existingIndex].expiresAt = max(current.sessions[existingIndex].expiresAt, expiresAt)
            try persist(current)
            return AppCommandState(
                vault: current, groupState: groupState,
                pendingDeviceRequest: state.pendingDeviceRequest
            )
        }
        var record = SessionRecord(
            protocolVersion: pairing.protocolVersion, sessionID: pairing.sessionID, groupID: group.groupID,
            creatorPublicKey: pairing.creatorPublicKey, keys: [:], cursor: 0,
            title: "Session \(pairing.sessionID.prefix(8))", status: "Connected", notifications: [],
            request: nil, requestKeyTimestamp: nil, color: pairing.color,
            updatedAt: Self.currentTimeMilliseconds(), expiresAt: expiresAt
        )
        try Self.populateSessionKeys(&record, group: group)
        current.sessions.append(record)
        try persist(current)
        return AppCommandState(
            vault: current, groupState: groupState,
            pendingDeviceRequest: state.pendingDeviceRequest
        )
    }

    private func approveDeviceAddition(
        groupID: String,
        requestURL: String,
        state: AppCommandState
    ) async throws -> AppCommandState {
        try requireGroup(groupID, vault: state.vault)
        let link = try DeviceRequestLink(requestURL)
        var current = state.vault
        guard current.identity.group != nil, state.pendingDeviceRequest == nil else {
            throw ProtocolError.invalidPairingLink("this device cannot add another device to a group")
        }
        var groupState = try await synchronizeGroup(&current)
        groupState = try await ensureExactGroupKey(&current, groupState: groupState)
        if try Self.inheritSessions(&current, groupState: groupState) { try persist(current) }
        let request = try await api.deviceRequestForApproval(identity: current.identity, requestID: link.requestID)
        let requestHash = CryptoEngine.deviceRequestBindingHash(
            requestID: request.requestID, deviceID: request.deviceID,
            signingPublicKey: request.signingPublicKey, accessHash: request.accessHash,
            encryptionPublicKey: request.encryptionPublicKey, protocolVersion: request.protocolVersion
        )
        guard requestHash == link.requestHash, request.protocolVersion == 4 else {
            throw ProtocolError.crypto("add-to-group link does not authenticate this device request")
        }
        guard !groupState.members.contains(where: { $0.deviceID == request.deviceID }) else {
            throw ProtocolError.invalidResponse("device is already in this group")
        }
        let members = groupState.members.map(Self.transitionMember) + [TransitionMember(
            deviceID: request.deviceID, signingPublicKey: request.signingPublicKey,
            encryptionPublicKey: request.encryptionPublicKey
        )]
        let update = try createMembershipTransition(
            current: current, members: members, recreated: false, groupState: groupState
        )
        let approvalProof = try CryptoEngine.deviceApprovalProof(
            authSecret: link.authSecret, requestID: link.requestID,
            groupID: current.identity.group!.groupID, transitionHash: update.transition.transitionHash
        )
        try await api.approveDeviceRequest(
            identity: current.identity, requestID: link.requestID,
            transition: update.transition, packages: update.packages, approvalProof: approvalProof
        )
        try storeTransitionKey(update, in: &current)
        groupState = try await synchronizeGroup(&current)
        groupState = try await ensureExactGroupKey(&current, groupState: groupState)
        _ = try Self.inheritSessions(&current, groupState: groupState)
        try persist(current)
        return AppCommandState(
            vault: current, groupState: groupState,
            pendingDeviceRequest: state.pendingDeviceRequest
        )
    }

    private func prepareDeviceGroupJoin(
        groupID: String,
        discardSavedSessions: Bool,
        state: AppCommandState
    ) async throws -> AppCommandState {
        try requireGroup(groupID, vault: state.vault)
        var current = state.vault
        let groupState = try await synchronizeGroup(&current)
        if try Self.inheritSessions(&current, groupState: groupState) { try persist(current) }
        if (groupState.members.count > 1 || !current.sessions.isEmpty) && !discardSavedSessions {
            throw ProtocolError.invalidResponse("confirm removing this device from its current group and deleting its saved sessions")
        }
        if let groupID = current.identity.group?.groupID {
            guard let head = current.identity.group?.headTransitionHash else {
                throw ProtocolError.crypto("group transition head is unavailable")
            }
            if groupState.members.count == 1 {
                try await api.abandonGroup(identity: current.identity, headTransitionHash: head)
            } else {
                let update = try createSelfRemovalTransition(
                    current: current,
                    members: groupState.members.filter { $0.deviceID != current.identity.deviceID }.map(Self.transitionMember),
                    groupState: groupState
                )
                try await api.removeDevice(
                    identity: current.identity, deviceID: current.identity.deviceID,
                    transition: update.transition, packages: update.packages
                )
            }
            current = Self.detachingFromDeviceGroup(current, groupID: groupID)
        }
        let requestID = try CryptoEngine.randomID()
        let authSecret = try CryptoEngine.randomToken()
        let created = try await api.createDeviceRequest(
            identity: current.identity, requestID: requestID, authSecret: authSecret
        )
        try persist(current)
        return AppCommandState(
            vault: current, groupState: nil, pendingDeviceRequest: created
        )
    }

    private func removeDevice(
        groupID: String,
        deviceID: String,
        state: AppCommandState,
        groupState: DeviceGroupStateResult
    ) async throws -> AppCommandState {
        try requireGroup(groupID, vault: state.vault)
        var current = state.vault
        let update = try createMembershipTransition(
            current: current,
            members: groupState.members.filter { $0.deviceID != deviceID }.map(Self.transitionMember),
            recreated: true,
            groupState: groupState
        )
        try await api.removeDevice(
            identity: current.identity, deviceID: deviceID,
            transition: update.transition, packages: update.packages
        )
        try storeTransitionKey(update, in: &current)
        var groupState = try await synchronizeGroup(&current)
        groupState = try await ensureExactGroupKey(&current, groupState: groupState)
        _ = try Self.inheritSessions(&current, groupState: groupState)
        try persist(current)
        return AppCommandState(
            vault: current, groupState: groupState,
            pendingDeviceRequest: state.pendingDeviceRequest
        )
    }

    private func leaveDeviceGroup(
        groupID: String,
        state: AppCommandState,
        groupState: DeviceGroupStateResult
    ) async throws -> AppCommandState {
        try requireGroup(groupID, vault: state.vault)
        var current = state.vault
        guard groupState.members.count > 1 else {
            throw ProtocolError.invalidResponse("this device cannot be removed from a group with no other devices")
        }
        let update = try createSelfRemovalTransition(
            current: current,
            members: groupState.members.filter { $0.deviceID != current.identity.deviceID }.map(Self.transitionMember),
            groupState: groupState
        )
        try await api.removeDevice(
            identity: current.identity, deviceID: current.identity.deviceID,
            transition: update.transition, packages: update.packages
        )
        current = Self.detachingFromDeviceGroup(current, groupID: groupID)
        let groupState = try await createSoloGroup(&current)
        try persist(current)
        return AppCommandState(
            vault: current, groupState: groupState, pendingDeviceRequest: nil
        )
    }

    private func respond(
        sessionID: String,
        requestID: String,
        optionID: String,
        vault: Vault,
        groupState: DeviceGroupStateResult
    ) async throws -> Vault {
        var current = vault
        guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
              let group = current.identity.group,
              let key = try Self.currentGroupKey(state: groupState, group: group) else {
            throw ProtocolError.invalidResponse("request is no longer available")
        }
        try Self.populateSessionKeys(&current.sessions[index], group: group)
        let timestamp = key.timestamp
        let responseID = try CryptoEngine.randomID()
        let payload = try CryptoEngine.encryptResponse(
            session: current.sessions[index], timestamp: timestamp, responseID: responseID,
            requestID: requestID, optionID: optionID, createdAt: ISO8601DateFormatter().string(from: Date())
        )
        current.sessions[index].expiresAt = try await api.postResponse(
            session: current.sessions[index], identity: current.identity, timestamp: timestamp,
            responseID: responseID, itemID: requestID, payload: payload
        )
        if current.sessions[index].request?.id == requestID {
            current.sessions[index].request = nil
            current.sessions[index].requestKeyTimestamp = nil
            current.sessions[index].status = "Response sent"
        }
        try persist(current)
        return current
    }

    private func setAttention(
        sessionID: String,
        enabled: Bool,
        vault: Vault
    ) async throws -> Vault {
        var current = vault
        guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }) else {
            throw ProtocolError.invalidResponse("session is no longer available")
        }
        try await api.setAttention(session: current.sessions[index], identity: current.identity, attention: enabled)
        current.sessions[index].attention = enabled
        try persist(current)
        return current
    }

    private func sendFeedback(
        sessionID: String,
        message: String,
        photos: [PreparedPhoto],
        vault: Vault,
        groupState: DeviceGroupStateResult
    ) async throws {
        guard let session = vault.sessions.first(where: { $0.sessionID == sessionID }),
              let group = vault.identity.group,
              let key = try Self.currentGroupKey(state: groupState, group: group) else {
            throw ProtocolError.invalidResponse("session feedback key is unavailable")
        }
        try await api.sendFeedback(
            session: session, identity: vault.identity, key: key,
            message: message, photos: photos
        )
    }

    private func createSelfRemovalTransition(
        current: Vault,
        members: [TransitionMember],
        groupState: DeviceGroupStateResult
    ) throws -> (key: GroupKey, packages: [KeyPackage], transition: GroupKeyRecord) {
        guard let group = current.identity.group, let previous = groupState.keys.last,
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

    nonisolated static func detachingFromDeviceGroup(_ vault: Vault, groupID: String) -> Vault {
        var result = vault
        result.identity.group = nil
        result.sessions.removeAll {
            ($0.protocolVersion == 3 || $0.protocolVersion == 4) && $0.groupID == groupID
        }
        return result
    }

    private func dismissRequest(
        sessionID: String,
        requestID: String,
        vault: Vault,
        groupState: DeviceGroupStateResult
    ) async throws -> Vault {
        var current = vault
        guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
              let group = current.identity.group,
              let key = try Self.currentGroupKey(state: groupState, group: group) else {
            throw ProtocolError.invalidResponse("request is no longer available")
        }
        try Self.populateSessionKeys(&current.sessions[index], group: group)
        let timestamp = key.timestamp
        let responseID = try CryptoEngine.randomID()
        let createdAt = RFC3339.string(from: Date())
        let payload = try CryptoEngine.encryptDismiss(
            session: current.sessions[index], timestamp: timestamp, responseID: responseID,
            eventID: requestID, createdAt: createdAt
        )
        current.sessions[index].expiresAt = try await api.postResponse(
            session: current.sessions[index], identity: current.identity, timestamp: timestamp,
            responseID: responseID, itemID: requestID, payload: payload
        )
        if current.sessions[index].request?.id == requestID {
            current.sessions[index].request = nil
            current.sessions[index].requestKeyTimestamp = nil
            current.sessions[index].status = "Request dismissed"
        }
        try persist(current)
        return current
    }

    private func dismissNotification(
        sessionID: String,
        notificationID: String,
        vault: Vault,
        groupState: DeviceGroupStateResult
    ) async throws -> Vault {
        var current = vault
        guard let sessionIndex = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
              let notificationIndex = current.sessions[sessionIndex].notifications.firstIndex(where: { $0.id == notificationID }) else {
            throw ProtocolError.invalidResponse("notification is no longer available")
        }
        let notification = current.sessions[sessionIndex].notifications[notificationIndex]
        if let itemID = notification.serverItemID {
            guard let group = current.identity.group,
                  let key = try Self.currentGroupKey(state: groupState, group: group) else {
                throw ProtocolError.invalidResponse("notification dismissal key is unavailable")
            }
            try Self.populateSessionKeys(&current.sessions[sessionIndex], group: group)
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
        return current
    }

    static func currentGroupKey(state: DeviceGroupStateResult, group: DeviceGroup) throws -> GroupKey? {
        guard let record = GroupKeyPolicy.selectUsableKey(state) else { return nil }
        guard let key = group.keys[String(record.timestamp)], key.publicKey == record.publicKey else {
            throw ProtocolError.crypto("current group private key is unavailable")
        }
        guard key.transitionHash == record.transitionHash else {
            throw ProtocolError.crypto("current group key transition is not authenticated")
        }
        return key
    }

    private func synchronize(
        state initialState: AppCommandState
    ) async throws -> AppCommandResult {
        try Task.checkCancellation()
        var current = initialState.vault
        var groupState = initialState.groupState
        var pendingDeviceRequest = initialState.pendingDeviceRequest
        var changes: [SynchronizationChange] = []
        current.sessions.removeAll { $0.expiresAt <= Self.currentTimeMilliseconds() }
        if current != initialState.vault { try persist(current) }
        do {
            if let pending = pendingDeviceRequest {
                let result = try await pollDeviceRequest(
                    vault: current, pendingDeviceRequest: pending
                )
                current = result.nextState.vault
                groupState = result.nextState.groupState
                pendingDeviceRequest = result.nextState.pendingDeviceRequest
                changes.append(contentsOf: result.changes)
            }
            if current.identity.group != nil {
                var synchronizedGroupState = try await synchronizeGroup(&current)
                synchronizedGroupState = try await ensureExactGroupKey(
                    &current, groupState: synchronizedGroupState
                )
                groupState = synchronizedGroupState
                if try Self.inheritSessions(
                    &current, groupState: synchronizedGroupState
                ) { try persist(current) }
                guard let group = current.identity.group else {
                    throw ProtocolError.invalidResponse("device group disappeared during synchronization")
                }
                let sessionIDs = current.sessions.filter { $0.groupID == group.groupID }.map(\.sessionID)
                for sessionID in sessionIDs {
                    try Task.checkCancellation()
                    guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }) else {
                        throw ProtocolError.invalidResponse("session disappeared during synchronization")
                    }
                    do {
                        try Self.populateSessionKeys(&current.sessions[index], group: group)
                        let result = try await api.events(for: current.sessions[index], identity: current.identity)
                        for envelope in result.events {
                            let event = try CryptoEngine.decryptEvent(session: current.sessions[index], envelope: envelope)
                            try Self.apply(
                                event, timestamp: envelope.keyTimestamp, createdAt: envelope.createdAt,
                                serverItemID: envelope.itemID, to: &current.sessions[index]
                            )
                            current.sessions[index].cursor = envelope.sequence
                            current.sessions[index].updatedAt = envelope.createdAt
                        }
                        Self.reconcileActiveItems(result.activeItemIDs, in: &current.sessions[index])
                        current.sessions[index].attention = result.attention
                        current.sessions[index].expiresAt = result.expiresAt
                    } catch let error as APIError
                        where (error.status == 404 && error.code == "session_not_found")
                           || (error.status == 410 && error.code == "session_expired") {
                        current.sessions.remove(at: index)
                    } catch let error as APIError where error.status == 403 && error.code == "device_removed" {
                        throw error
                    } catch where Self.isCancellation(error) {
                        throw error
                    } catch {
                        throw SessionSynchronizationError(
                            sessionID: sessionID, underlyingError: error
                        )
                    }
                }
            } else if pendingDeviceRequest == nil {
                throw ProtocolError.invalidResponse("device group is unavailable")
            }
            current.sessions.removeAll { $0.expiresAt <= Self.currentTimeMilliseconds() }
            try persist(current)
        } catch let error as APIError where error.status == 403 && error.code == "device_removed" {
            let result = try await recoverRemovedDevice(vault: current)
            current = result.nextState.vault
            groupState = result.nextState.groupState
            pendingDeviceRequest = result.nextState.pendingDeviceRequest
            changes.append(contentsOf: result.changes)
        }
        return AppCommandResult(
            nextState: AppCommandState(
                vault: current,
                groupState: groupState,
                pendingDeviceRequest: pendingDeviceRequest
            ),
            changes: changes
        )
    }

    private func pollDeviceRequest(
        vault: Vault,
        pendingDeviceRequest: DeviceRequestRecord
    ) async throws -> AppCommandResult {
        var current = vault
        switch try await api.deviceRequestStatus(
            identity: current.identity, requestID: pendingDeviceRequest.requestID
        ) {
        case .waiting, .approving:
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: current, groupState: nil,
                    pendingDeviceRequest: pendingDeviceRequest
                ),
                changes: []
            )
        case .expired:
            let groupState = try await createSoloGroup(&current)
            try persist(current)
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: current, groupState: groupState,
                    pendingDeviceRequest: nil
                ),
                changes: [.deviceRequestExpired]
            )
        case .approved(let groupID, _, let transitionHash, let approvalProof):
            guard try CryptoEngine.verifyDeviceApprovalProof(
                authSecret: pendingDeviceRequest.authSecret,
                requestID: pendingDeviceRequest.requestID,
                groupID: groupID, transitionHash: transitionHash, proof: approvalProof
            ) else { throw ProtocolError.crypto("device approval proof is invalid") }
            current.identity.group = DeviceGroup(
                groupID: groupID, keys: [:], pendingTransitionHash: transitionHash
            )
            var groupState = try await synchronizeGroup(&current)
            groupState = try await ensureExactGroupKey(&current, groupState: groupState)
            return AppCommandResult(
                nextState: AppCommandState(
                    vault: current, groupState: groupState,
                    pendingDeviceRequest: nil
                ),
                changes: [.deviceAdded]
            )
        }
    }

    private func recoverRemovedDevice(vault: Vault) async throws -> AppCommandResult {
        var current = vault
        guard let groupID = current.identity.group?.groupID else {
            throw ProtocolError.invalidResponse("removed device has no local group")
        }
        current.identity.group = nil
        current.sessions.removeAll {
            ($0.protocolVersion == 3 || $0.protocolVersion == 4) && $0.groupID == groupID
        }
        let groupState = try await createSoloGroup(&current)
        try persist(current)
        return AppCommandResult(
            nextState: AppCommandState(
                vault: current, groupState: groupState,
                pendingDeviceRequest: nil
            ),
            changes: [.deviceRemoved]
        )
    }

    private func persist(_ value: Vault) throws {
        try storage.save(value)
    }

    nonisolated private static func currentTimeMilliseconds() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1_000)
    }

    nonisolated private static func isCancellation(_ error: Error) -> Bool {
        error is CancellationError || (error as? URLError)?.code == .cancelled
    }

    private func createSoloGroup(
        _ current: inout Vault
    ) async throws -> DeviceGroupStateResult {
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
        var groupState = try await synchronizeGroup(&current)
        groupState = try await ensureExactGroupKey(&current, groupState: groupState)
        return groupState
    }

    private func synchronizeGroup(
        _ current: inout Vault
    ) async throws -> DeviceGroupStateResult {
        guard var group = current.identity.group else {
            throw ProtocolError.crypto("device group is unavailable")
        }
        let state = try await api.groupState(identity: current.identity)
        guard let trustedHash = group.headTransitionHash ?? group.pendingTransitionHash else {
            throw ProtocolError.crypto("device group has no authenticated transition anchor")
        }
        let head = try CryptoEngine.validateGroupTransitions(
            groupID: state.groupID, transitions: state.keys, trustedHash: trustedHash
        )
        guard Self.sameTransitionMembers(head.members, state.members.map(Self.transitionMember)) else {
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
        try persist(current)
        return state
    }

    private func ensureExactGroupKey(
        _ current: inout Vault,
        groupState: DeviceGroupStateResult
    ) async throws -> DeviceGroupStateResult {
        guard GroupKeyPolicy.latestKeyMatchesMembers(groupState) else {
            throw ProtocolError.crypto("device group key does not match its authenticated members")
        }
        guard GroupKeyPolicy.needsRecreation(groupState) else { return groupState }
        let update = try createMembershipTransition(
            current: current,
            members: groupState.members.map(Self.transitionMember),
            recreated: true,
            groupState: groupState
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
            return try await synchronizeGroup(&current)
        }
        return try await synchronizeGroup(&current)
    }

    private func createMembershipTransition(
        current: Vault,
        members: [TransitionMember],
        recreated: Bool,
        groupState: DeviceGroupStateResult
    ) throws -> (key: GroupKey, packages: [KeyPackage], transition: GroupKeyRecord) {
        guard let group = current.identity.group, let previous = groupState.keys.last,
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

    static func transitionMember(_ device: GroupDevice) -> TransitionMember {
        TransitionMember(
            deviceID: device.deviceID, signingPublicKey: device.signingPublicKey,
            encryptionPublicKey: device.encryptionPublicKey
        )
    }

    static func sameTransitionMembers(_ left: [TransitionMember], _ right: [TransitionMember]) -> Bool {
        let normalize: ([TransitionMember]) -> [String] = { members in
            members.sorted { $0.deviceID.utf8.lexicographicallyPrecedes($1.deviceID.utf8) }
                .map { "\($0.deviceID)\n\($0.signingPublicKey)\n\($0.encryptionPublicKey)" }
        }
        return normalize(left) == normalize(right)
    }

    nonisolated static func inheritSessions(
        _ current: inout Vault,
        groupState: DeviceGroupStateResult
    ) throws -> Bool {
        guard let group = current.identity.group else { throw ProtocolError.crypto("device group is unavailable") }
        let previousSessions = current.sessions
        let authenticated = try CryptoEngine.authenticatedInheritedSessions(
            groupState.sessions, groupID: group.groupID, transitions: groupState.keys
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
                try Self.populateSessionKeys(&record, group: group)
            } catch {
                throw SessionSynchronizationError(
                    sessionID: remote.sessionID, underlyingError: error
                )
            }
            nextSessions.append(record)
            localSessionIDs.insert(remote.sessionID)
        }
        current.sessions = nextSessions
        return current.sessions != previousSessions
    }

    nonisolated static func populateSessionKeys(
        _ session: inout SessionRecord,
        group: DeviceGroup
    ) throws {
        for key in group.keys.values where session.keys[String(key.timestamp)] == nil {
            session.keys[String(key.timestamp)] = try CryptoEngine.deriveSessionKey(
                key: key, creatorPublicKey: session.creatorPublicKey, sessionID: session.sessionID,
                groupID: group.groupID, protocolVersion: session.protocolVersion
            )
        }
    }

    static func apply(
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

    static func reconcileActiveItems(_ activeItemIDs: [String], in session: inout SessionRecord) {
        let active = Set(activeItemIDs)
        session.notifications.removeAll { notification in
            notification.serverItemID.map { !active.contains($0) } ?? false
        }
        if let itemID = session.request?.serverItemID, !active.contains(itemID) {
            session.request = nil
            session.requestKeyTimestamp = nil
        }
    }
}
