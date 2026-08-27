import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var sessions: [SessionRecord] = []
    @Published private(set) var groupDevices: [GroupDevice] = []
    @Published private(set) var pendingDevices: [PendingDevice] = []
    @Published private(set) var groupGeneration: Int64?
    @Published private(set) var deviceID: String?
    @Published private(set) var invitationLink: String?
    @Published private(set) var verificationCode: String?
    @Published private(set) var deviceJoinStatus: String?
    @Published private(set) var connectionState: ConnectionState = .preparing
    @Published private(set) var isReady = false
    @Published var errorMessage: String?

    private let keychain = KeychainVault()
    private let api = APIClient()
    private var vault: Vault?
    private var groupState: DeviceGroupStateResult?
    private var isSyncing = false

    func start() async {
        guard !isReady else { return }
        do {
            PushCoordinator.shared.onToken = { [weak self] token, environment in
                guard let self else { return }
                Task { await self.registerPushToken(token, environment: environment) }
            }
            PushCoordinator.shared.onFailure = { [weak self] error in self?.show(error) }
            let loaded = try keychain.load()
            let initial: Vault
            if let loaded {
                initial = loaded
            } else {
                initial = Vault(version: 2, identity: try CryptoEngine.createIdentity(), sessions: [])
            }
            let current = Self.pruningExpiredSessions(from: initial, nowMilliseconds: Self.currentTimeMilliseconds())
            if loaded == nil || current != initial { try keychain.save(current) }
            vault = current
            publish(current)
            isReady = true
            await sync()
            await resumeNotifications()
        } catch {
            show(error)
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
        let value = link.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            if let components = URLComponents(string: value), components.path == "/device" {
                try await joinDevice(DeviceInvitationLink(value))
            } else {
                try await joinSession(PairingLink(value))
            }
            errorMessage = nil
            await sync()
            return true
        } catch {
            show(error)
            return false
        }
    }

    func createDeviceInvitation() async {
        do {
            var current = requiredVault()
            try await synchronizeGroup(&current)
            guard let group = current.identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
            let invitationID = try CryptoEngine.randomID()
            let token = try CryptoEngine.randomToken()
            let expiresAt = try await api.createInvitation(
                identity: current.identity,
                invitationID: invitationID,
                tokenHash: CryptoEngine.hashToken(token)
            )
            let invitation = DeviceInvitationRecord(
                groupID: group.groupID,
                invitationID: invitationID,
                invitationToken: token,
                revision: group.revision,
                generation: group.generation,
                publicKey: group.publicKey,
                expiresAt: expiresAt
            )
            current.identity.invitations[invitationID] = invitation
            try persist(current)
            invitationLink = try deviceInvitationURL(invitation)
        } catch { show(error) }
    }

    func verificationCode(for pending: PendingDevice) -> String? {
        guard let invitation = vault?.identity.invitations[pending.invitationID] else { return nil }
        return CryptoEngine.verificationCode(invitation: invitation, pending: pending)
    }

    func approve(invitationID: String) async {
        do {
            var current = requiredVault()
            guard let pending = groupState?.pending.first(where: { $0.invitationID == invitationID }),
                  current.identity.invitations[invitationID] != nil else {
                throw ProtocolError.invalidResponse("pending invitation details are unavailable")
            }
            let transition = try buildTransition(action: "add", targetDeviceID: pending.deviceID, pending: pending, vault: current)
            try await api.approveJoin(identity: current.identity, invitationID: invitationID, body: transition.body)
            applyLocalTransition(next: transition.next, to: &current)
            current.identity.invitations.removeValue(forKey: invitationID)
            try persist(current)
            await sync()
        } catch { show(error) }
    }

    func reject(invitationID: String) async {
        do {
            var current = requiredVault()
            try await api.rejectJoin(identity: current.identity, invitationID: invitationID)
            current.identity.invitations.removeValue(forKey: invitationID)
            try persist(current)
            await sync()
        } catch { show(error) }
    }

    func remove(deviceID: String) async {
        do {
            var current = requiredVault()
            let transition = try buildTransition(action: "remove", targetDeviceID: deviceID, pending: nil, vault: current)
            try await api.removeDevice(identity: current.identity, deviceID: deviceID, body: transition.body)
            applyLocalTransition(next: transition.next, to: &current)
            try persist(current)
            await sync()
        } catch { show(error) }
    }

    func respond(sessionID: String, optionID: String) async {
        do {
            try pruneExpiredSessions()
            var current = requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let request = current.sessions[index].request,
                  request.options.contains(where: { $0.id == optionID }) else {
                throw ProtocolError.invalidEvent("request or selected option disappeared")
            }
            let responseID = try CryptoEngine.randomID()
            let generation = current.sessions[index].requestGeneration
            let payload = try CryptoEngine.encryptResponse(
                session: current.sessions[index],
                generation: generation,
                responseID: responseID,
                requestID: request.id,
                optionID: optionID,
                createdAt: RFC3339.string(from: Date())
            )
            let expiresAt = try await api.postResponse(
                session: current.sessions[index],
                identity: current.identity,
                generation: generation,
                responseID: responseID,
                payload: payload
            )
            current.sessions[index].request = nil
            current.sessions[index].requestGeneration = nil
            current.sessions[index].status = "Response sent"
            current.sessions[index].expiresAt = expiresAt
            try persist(current)
            errorMessage = nil
        } catch { show(error) }
    }

    func sync() async {
        guard isReady, !isSyncing else { return }
        isSyncing = true
        connectionState = .syncing
        defer { isSyncing = false }
        do {
            try pruneExpiredSessions()
            var current = requiredVault()
            if current.identity.pendingInvitation != nil {
                try await pollDeviceJoin(&current)
            }
            if current.identity.group != nil, current.identity.pendingInvitation == nil {
                try await synchronizeGroup(&current)
                try await inheritSessions(&current)
            }
            var index = 0
            while index < current.sessions.count {
                do {
                    let result = try await api.events(for: current.sessions[index], identity: current.identity)
                    for envelope in result.events {
                        guard envelope.sequence > current.sessions[index].cursor else {
                            throw ProtocolError.invalidResponse("event sequence did not advance")
                        }
                        let event = try CryptoEngine.decryptEvent(session: current.sessions[index], envelope: envelope)
                        apply(event, generation: envelope.generation, to: &current.sessions[index])
                        current.sessions[index].cursor = envelope.sequence
                    }
                    current.sessions[index].expiresAt = result.expiresAt
                    index += 1
                } catch let error as APIError where error.code == "session_not_found" || error.code == "session_expired" {
                    current.sessions.remove(at: index)
                }
            }
            if current != requiredVault() { try persist(current) }
            connectionState = .current
        } catch {
            if isExpectedCancellation(error) { connectionState = .current; return }
            connectionState = .failed
            show(error)
        }
    }

    func dismissError() { errorMessage = nil }

    func resumeNotifications() async {
        guard isReady, !sessions.isEmpty else { return }
        await PushCoordinator.shared.resumeIfAuthorized()
    }

    private func joinSession(_ pairing: PairingLink) async throws {
        try pruneExpiredSessions()
        var current = requiredVault()
        guard !current.sessions.contains(where: { $0.sessionID == pairing.sessionID }) else {
            throw ProtocolError.invalidPairingLink("this device group already joined the session")
        }
        if current.identity.group == nil { try await createInitialGroup(&current) }
        try await synchronizeGroup(&current)
        guard let group = current.identity.group else { throw ProtocolError.invalidResponse("device group is not ready") }
        let expiresAt = try await api.join(pairing, identity: current.identity)
        var record = SessionRecord(
            protocolVersion: 2,
            sessionID: pairing.sessionID,
            groupID: group.groupID,
            groupAccessToken: "",
            sharedKey: Data(),
            creatorPublicKey: pairing.creatorPublicKey,
            generationKeys: [:],
            cursor: 0,
            title: "Session \(pairing.sessionID.prefix(8))",
            status: "Connected",
            notification: "",
            request: nil,
            requestGeneration: nil,
            expiresAt: expiresAt
        )
        try populateSessionKeys(&record, group: group)
        current.sessions.append(record)
        try persist(current)
        await enableNotifications()
    }

    private func joinDevice(_ link: DeviceInvitationLink) async throws {
        var current = requiredVault()
        guard current.identity.group == nil else {
            throw ProtocolError.invalidPairingLink("this device already belongs to a device group")
        }
        let expiresAt = try await api.submitJoinRequest(link, identity: current.identity)
        let invitation = DeviceInvitationRecord(
            groupID: link.groupID,
            invitationID: link.invitationID,
            invitationToken: link.invitationToken,
            revision: link.revision,
            generation: link.generation,
            publicKey: link.publicKey,
            expiresAt: expiresAt
        )
        current.identity.group = DeviceGroup(
            groupID: link.groupID,
            revision: link.revision,
            generation: link.generation,
            publicKey: link.publicKey,
            generations: [:]
        )
        current.identity.pendingInvitation = invitation
        let own = PendingDevice(
            invitationID: link.invitationID,
            deviceID: current.identity.deviceID,
            encryptionPublicKey: try CryptoEngine.encryptionPublicKey(for: current.identity),
            signingPublicKey: try CryptoEngine.signingPublicKey(for: current.identity),
            createdAt: 0,
            expiresAt: expiresAt
        )
        verificationCode = CryptoEngine.verificationCode(invitation: invitation, pending: own)
        deviceJoinStatus = "Confirm this code on the inviting device."
        try persist(current)
    }

    private func createInitialGroup(_ current: inout Vault) async throws {
        let groupID = try CryptoEngine.randomID()
        let generation = CryptoEngine.createGeneration(1)
        let package = try CryptoEngine.createKeyPackage(
            groupID: groupID,
            generation: generation,
            deviceID: current.identity.deviceID,
            encryptionPublicKey: CryptoEngine.encryptionPublicKey(for: current.identity)
        )
        let packagesHash = CryptoEngine.hashPackages([package])
        let transcript = try CryptoEngine.groupCreateTranscript(
            groupID: groupID, identity: current.identity, generation: generation, packagesHash: packagesHash
        )
        try await api.createGroup(
            groupID: groupID,
            identity: current.identity,
            generation: generation,
            package: package,
            deviceSignature: CryptoEngine.signDevice(identity: current.identity, transcript: transcript)
        )
        current.identity.group = DeviceGroup(
            groupID: groupID,
            revision: 1,
            generation: 1,
            publicKey: generation.publicKey,
            generations: ["1": generation]
        )
        try persist(current)
    }

    private func pollDeviceJoin(_ current: inout Vault) async throws {
        guard let invitation = current.identity.pendingInvitation else { return }
        let status = try await api.joinRequestStatus(invitation)
        switch status {
        case "approved":
            try await synchronizeGroup(&current)
            current.identity.pendingInvitation = nil
            deviceJoinStatus = "This device joined the group."
            try persist(current)
        case "rejected", "expired":
            deviceJoinStatus = status == "rejected"
                ? "The device invitation was rejected."
                : "The device invitation expired."
            current.identity.pendingInvitation = nil
            current.identity.group = nil
            verificationCode = nil
            try persist(current)
        case "waiting", "pending": break
        default: throw ProtocolError.invalidResponse("unknown join request status")
        }
    }

    private func synchronizeGroup(_ current: inout Vault) async throws {
        guard var group = current.identity.group else { return }
        let after: Int64 = current.identity.pendingInvitation == nil ? group.generation : 0
        let state = try await api.groupState(identity: current.identity, afterGeneration: after)
        var revision = group.revision
        var generation = group.generation
        var publicKey = group.publicKey
        var publicKeys = [String(generation): publicKey]
        for transition in state.transitions where transition.generation > generation {
            guard transition.revision == revision + 1,
                  transition.previousGeneration == generation,
                  transition.generation == generation + 1 else {
                throw ProtocolError.crypto("device group transition chain is discontinuous")
            }
            let transcript = CryptoEngine.transitionTranscript(groupID: group.groupID, transition: transition)
            guard try CryptoEngine.verify(
                publicKey: publicKey,
                signature: transition.groupSignature,
                transcript: transcript
            ) else {
                throw ProtocolError.crypto("device group transition signature is invalid")
            }
            revision = transition.revision
            generation = transition.generation
            publicKey = transition.generationPublicKey
            publicKeys[String(generation)] = publicKey
        }
        guard revision == state.revision, generation == state.generation, publicKey == state.generationPublicKey else {
            throw ProtocolError.crypto("device group current state does not match its signed chain")
        }
        for package in state.packages where group.generations[String(package.generation)] == nil {
            let expected = package.generation > group.generation ? publicKeys[String(package.generation)] : nil
            group.generations[String(package.generation)] = try CryptoEngine.openKeyPackage(
                identity: current.identity, groupID: group.groupID, expectedPublicKey: expected, package: package
            )
        }
        guard group.generations[String(generation)] != nil else {
            throw ProtocolError.crypto("current generation key package is missing")
        }
        group.revision = revision
        group.generation = generation
        group.publicKey = publicKey
        current.identity.group = group
        for index in current.sessions.indices where current.sessions[index].protocolVersion == 2 {
            try populateSessionKeys(&current.sessions[index], group: group)
        }
        groupState = state
        groupDevices = state.devices
        pendingDevices = state.pending
        groupGeneration = generation
        try persist(current)
    }

    private func inheritSessions(_ current: inout Vault) async throws {
        guard let group = current.identity.group else { return }
        for remote in try await api.groupSessions(identity: current.identity)
            where !current.sessions.contains(where: { $0.sessionID == remote.sessionID }) {
            var record = SessionRecord(
                protocolVersion: 2,
                sessionID: remote.sessionID,
                groupID: group.groupID,
                groupAccessToken: "",
                sharedKey: Data(),
                creatorPublicKey: remote.creatorPublicKey,
                generationKeys: [:],
                cursor: 0,
                title: "Session \(remote.sessionID.prefix(8))",
                status: "Connected",
                notification: "",
                request: nil,
                requestGeneration: nil,
                expiresAt: remote.expiresAt
            )
            try populateSessionKeys(&record, group: group)
            current.sessions.append(record)
        }
    }

    private func populateSessionKeys(_ session: inout SessionRecord, group: DeviceGroup) throws {
        guard let creatorPublicKey = session.creatorPublicKey else {
            throw ProtocolError.crypto("v2 session is missing its creator public key")
        }
        for generation in group.generations.values where session.generationKeys[String(generation.generation)] == nil {
            session.generationKeys[String(generation.generation)] = try CryptoEngine.deriveSessionKey(
                generation: generation,
                creatorPublicKey: creatorPublicKey,
                sessionID: session.sessionID,
                groupID: group.groupID
            )
        }
    }

    private func buildTransition(
        action: String,
        targetDeviceID: String,
        pending: PendingDevice?,
        vault: Vault
    ) throws -> (next: GenerationKey, body: GroupTransitionBody) {
        guard let state = groupState,
              let group = vault.identity.group,
              let currentKey = group.generations[String(group.generation)] else {
            throw ProtocolError.crypto("current group state or generation key is unavailable")
        }
        let next = CryptoEngine.createGeneration(group.generation + 1)
        var recipients = state.devices.map { ($0.deviceID, $0.encryptionPublicKey) }
        if let pending { recipients.append((pending.deviceID, pending.encryptionPublicKey)) }
        if action == "remove" { recipients.removeAll { $0.0 == targetDeviceID } }
        var packages = try recipients.map {
            try CryptoEngine.createKeyPackage(groupID: group.groupID, generation: next, deviceID: $0.0, encryptionPublicKey: $0.1)
        }
        if let pending {
            for previous in group.generations.values {
                packages.append(try CryptoEngine.createKeyPackage(
                    groupID: group.groupID,
                    generation: previous,
                    deviceID: pending.deviceID,
                    encryptionPublicKey: pending.encryptionPublicKey
                ))
            }
        }
        let packagesHash = CryptoEngine.hashPackages(packages)
        let signed = GenerationTransition(
            revision: group.revision + 1,
            previousGeneration: group.generation,
            generation: next.generation,
            generationPublicKey: next.publicKey,
            action: action,
            actorDeviceID: vault.identity.deviceID,
            targetDeviceID: targetDeviceID,
            packagesHash: packagesHash,
            groupSignature: "",
            deviceSignature: "",
            createdAt: 0
        )
        let transcript = CryptoEngine.transitionTranscript(groupID: group.groupID, transition: signed)
        return (next, GroupTransitionBody(
            expectedRevision: group.revision,
            nextGenerationPublicKey: next.publicKey,
            packages: packages,
            groupSignature: try CryptoEngine.signGeneration(currentKey, transcript: transcript),
            deviceSignature: try CryptoEngine.signDevice(identity: vault.identity, transcript: transcript)
        ))
    }

    private func applyLocalTransition(next: GenerationKey, to current: inout Vault) {
        current.identity.group?.revision += 1
        current.identity.group?.generation = next.generation
        current.identity.group?.publicKey = next.publicKey
        current.identity.group?.generations[String(next.generation)] = next
    }

    private func apply(_ event: SessionEvent, generation: Int64?, to session: inout SessionRecord) {
        switch event {
        case .notification(let title, let message): session.title = title; session.notification = message
        case .status(let title, let value): session.title = title; session.status = value
        case .request(let title, let value):
            session.title = title
            session.request = value
            session.requestGeneration = generation
        }
    }

    private func deviceInvitationURL(_ invitation: DeviceInvitationRecord) throws -> String {
        var fragment = URLComponents()
        fragment.queryItems = [
            URLQueryItem(name: "v", value: "1"),
            URLQueryItem(name: "g", value: invitation.groupID),
            URLQueryItem(name: "i", value: invitation.invitationID),
            URLQueryItem(name: "t", value: invitation.invitationToken),
            URLQueryItem(name: "r", value: String(invitation.revision)),
            URLQueryItem(name: "n", value: String(invitation.generation)),
            URLQueryItem(name: "k", value: invitation.publicKey),
        ]
        var result = URLComponents(string: "https://notify.guru/device")!
        result.percentEncodedFragment = fragment.percentEncodedQuery
        guard let value = result.url?.absoluteString else { throw ProtocolError.invalidResponse("could not construct device invitation URL") }
        return value
    }

    private func persist(_ value: Vault) throws {
        try keychain.save(value)
        vault = value
        publish(value)
    }

    private func publish(_ value: Vault) {
        sessions = value.sessions.sorted { $0.expiresAt > $1.expiresAt }
        groupGeneration = value.identity.group?.generation
        deviceID = value.identity.deviceID
    }

    private func enableNotifications() async {
        do { _ = try await PushCoordinator.shared.enable() } catch { show(error) }
    }

    private func registerPushToken(_ token: String, environment: PushEnvironment) async {
        do {
            try pruneExpiredSessions()
            var current = requiredVault()
            var index = 0
            while index < current.sessions.count {
                do {
                    current.sessions[index].expiresAt = try await api.registerPushToken(
                        token, environment: environment, session: current.sessions[index], identity: current.identity
                    )
                    index += 1
                } catch let error as APIError where error.code == "session_not_found" || error.code == "session_expired" {
                    current.sessions.remove(at: index)
                }
            }
            if current != requiredVault() { try persist(current) }
        } catch { show(error) }
    }

    private func requiredVault() -> Vault {
        guard let vault else { preconditionFailure("AppModel must be started before use") }
        return vault
    }

    private func show(_ error: Error) {
        guard !isExpectedCancellation(error) else { return }
        errorMessage = error.localizedDescription
    }

    private func pruneExpiredSessions() throws {
        let current = requiredVault()
        let pruned = Self.pruningExpiredSessions(from: current, nowMilliseconds: Self.currentTimeMilliseconds())
        if pruned != current { try persist(pruned) }
    }

    nonisolated static func pruningExpiredSessions(from vault: Vault, nowMilliseconds: Int64) -> Vault {
        var result = vault
        result.sessions.removeAll { $0.expiresAt <= nowMilliseconds }
        return result
    }

    nonisolated private static func currentTimeMilliseconds() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1_000)
    }

    private func isExpectedCancellation(_ error: Error) -> Bool {
        error is CancellationError || (error as? URLError)?.code == .cancelled
    }
}
