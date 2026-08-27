import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var sessions: [SessionRecord] = []
    @Published private(set) var connectionState: ConnectionState = .preparing
    @Published private(set) var isReady = false
    @Published var errorMessage: String?

    private let keychain = KeychainVault()
    private let api = APIClient()
    private var vault: Vault?
    private var isSyncing = false

    func start() async {
        guard !isReady else { return }
        do {
            PushCoordinator.shared.onToken = { [weak self] token, environment in
                guard let self else { return }
                Task { await self.registerPushToken(token, environment: environment) }
            }
            PushCoordinator.shared.onFailure = { [weak self] error in
                self?.show(error)
            }
            if let existing = try keychain.load() {
                vault = existing
            } else {
                let created = Vault(version: 1, identity: try CryptoEngine.createIdentity(), sessions: [])
                try keychain.save(created)
                vault = created
            }
            sessions = requiredVault().sessions
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
            do {
                try await Task.sleep(for: .seconds(2))
            } catch is CancellationError {
                return
            } catch {
                show(error)
                return
            }
        }
    }

    func join(link: String) async -> Bool {
        do {
            let pairing = try PairingLink(link.trimmingCharacters(in: .whitespacesAndNewlines))
            var current = requiredVault()
            guard !current.sessions.contains(where: { $0.sessionID == pairing.sessionID }) else {
                throw ProtocolError.invalidPairingLink("this device group already joined the session")
            }
            let groupAccessToken = try CryptoEngine.randomToken()
            let sharedKey = try CryptoEngine.deriveSessionKey(
                identity: current.identity,
                creatorPublicKey: pairing.creatorPublicKey,
                sessionID: pairing.sessionID
            )
            let expiresAt = try await api.join(pairing, identity: current.identity, groupAccessToken: groupAccessToken)
            current.sessions.append(SessionRecord(
                sessionID: pairing.sessionID,
                groupID: current.identity.groupID,
                groupAccessToken: groupAccessToken,
                sharedKey: sharedKey,
                cursor: 0,
                title: "Session \(pairing.sessionID.prefix(8))",
                status: "Connected",
                notification: "",
                request: nil,
                expiresAt: expiresAt
            ))
            try persist(current)
            errorMessage = nil
            await sync()
            await enableNotifications()
            return true
        } catch {
            show(error)
            return false
        }
    }

    func respond(sessionID: String, optionID: String) async {
        do {
            var current = requiredVault()
            guard let index = current.sessions.firstIndex(where: { $0.sessionID == sessionID }),
                  let request = current.sessions[index].request else {
                throw ProtocolError.invalidEvent("request disappeared before response")
            }
            guard request.options.contains(where: { $0.id == optionID }) else {
                throw ProtocolError.invalidEvent("selected option is not part of the request")
            }
            let responseID = try CryptoEngine.randomID()
            let payload = try CryptoEngine.encryptResponse(
                session: current.sessions[index],
                responseID: responseID,
                requestID: request.id,
                optionID: optionID,
                createdAt: RFC3339.string(from: Date())
            )
            let expiresAt = try await api.postResponse(
                session: current.sessions[index],
                responseID: responseID,
                payload: payload
            )
            current.sessions[index].request = nil
            current.sessions[index].status = "Response sent"
            current.sessions[index].expiresAt = expiresAt
            try persist(current)
            errorMessage = nil
        } catch {
            show(error)
        }
    }

    func sync() async {
        guard isReady, !isSyncing else { return }
        isSyncing = true
        connectionState = .syncing
        defer { isSyncing = false }
        do {
            var current = requiredVault()
            var index = 0
            while index < current.sessions.count {
                do {
                    let result = try await api.events(for: current.sessions[index])
                    for envelope in result.events {
                        guard envelope.sequence > current.sessions[index].cursor else {
                            throw ProtocolError.invalidResponse("event sequence did not advance")
                        }
                        let event = try CryptoEngine.decryptEvent(session: current.sessions[index], envelope: envelope)
                        apply(event, to: &current.sessions[index])
                        current.sessions[index].cursor = envelope.sequence
                    }
                    current.sessions[index].expiresAt = result.expiresAt
                    index += 1
                } catch let error as APIError
                    where error.code == "session_not_found" || error.code == "session_expired" {
                    current.sessions.remove(at: index)
                }
            }
            if current != requiredVault() {
                try persist(current)
            }
            connectionState = .current
        } catch {
            if isExpectedCancellation(error) {
                connectionState = .current
                return
            }
            connectionState = .failed
            show(error)
        }
    }

    func dismissError() {
        errorMessage = nil
    }

    func resumeNotifications() async {
        guard isReady, !sessions.isEmpty else { return }
        await PushCoordinator.shared.resumeIfAuthorized()
    }

    private func apply(_ event: SessionEvent, to session: inout SessionRecord) {
        switch event {
        case .notification(let title, let message):
            session.title = title
            session.notification = message
        case .status(let title, let value):
            session.title = title
            session.status = value
        case .request(let title, let value):
            session.title = title
            session.request = value
        }
    }

    private func persist(_ value: Vault) throws {
        try keychain.save(value)
        vault = value
        sessions = value.sessions.sorted { $0.expiresAt > $1.expiresAt }
    }

    private func enableNotifications() async {
        do {
            _ = try await PushCoordinator.shared.enable()
        } catch {
            show(error)
        }
    }

    private func registerPushToken(_ token: String, environment: PushEnvironment) async {
        do {
            var current = requiredVault()
            var index = 0
            while index < current.sessions.count {
                do {
                    current.sessions[index].expiresAt = try await api.registerPushToken(
                        token,
                        environment: environment,
                        session: current.sessions[index]
                    )
                    index += 1
                } catch let error as APIError
                    where error.code == "session_not_found" || error.code == "session_expired" {
                    current.sessions.remove(at: index)
                }
            }
            if current != requiredVault() {
                try persist(current)
            }
        } catch {
            show(error)
        }
    }

    private func requiredVault() -> Vault {
        guard let vault else {
            preconditionFailure("AppModel must be started before use")
        }
        return vault
    }

    private func show(_ error: Error) {
        guard !isExpectedCancellation(error) else { return }
        errorMessage = error.localizedDescription
    }

    private func isExpectedCancellation(_ error: Error) -> Bool {
        if error is CancellationError {
            return true
        }
        return (error as? URLError)?.code == .cancelled
    }
}
