import Foundation
import Security

struct KeychainVault {
    private let service = "guru.notify.app"
    private let account = "vault"

    func load() throws -> Vault? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError.operation("read", status)
        }
        let envelope = try JSONDecoder().decode(VersionEnvelope.self, from: data)
        if envelope.version == 1 {
            let legacy = try JSONDecoder().decode(LegacyVault.self, from: data)
            let migrated = Vault(
                version: 2,
                identity: try CryptoEngine.createIdentity(),
                sessions: legacy.sessions.map { session in
                    SessionRecord(
                        protocolVersion: 1,
                        sessionID: session.sessionID,
                        groupID: session.groupID,
                        groupAccessToken: session.groupAccessToken,
                        sharedKey: session.sharedKey,
                        creatorPublicKey: nil,
                        generationKeys: [:],
                        cursor: session.cursor,
                        title: session.title,
                        status: session.status,
                        notification: session.notification,
                        request: session.request,
                        requestGeneration: nil,
                        expiresAt: session.expiresAt
                    )
                }
            )
            try save(migrated)
            return migrated
        }
        guard envelope.version == 2 else { throw KeychainError.unsupportedVersion(envelope.version) }
        return try JSONDecoder().decode(Vault.self, from: data)
    }

    func save(_ vault: Vault) throws {
        guard vault.version == 2 else {
            throw KeychainError.unsupportedVersion(vault.version)
        }
        let data = try JSONEncoder().encode(vault)
        let key: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let updateStatus = SecItemUpdate(
            key as CFDictionary,
            [kSecValueData as String: data] as CFDictionary
        )
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw KeychainError.operation("update", updateStatus)
        }
        var addition = key
        addition[kSecValueData as String] = data
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addition as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KeychainError.operation("create", addStatus)
        }
    }
}

private struct VersionEnvelope: Decodable {
    let version: Int
}

private struct LegacyVault: Decodable {
    let version: Int
    let identity: LegacyIdentity
    let sessions: [LegacySession]
}

private struct LegacyIdentity: Decodable {
    let groupID: String
    let privateKey: Data
}

private struct LegacySession: Decodable {
    let sessionID: String
    let groupID: String
    let groupAccessToken: String
    let sharedKey: Data
    let cursor: Int64
    let title: String
    let status: String
    let notification: String
    let request: SessionRequest?
    let expiresAt: Int64
}

enum KeychainError: LocalizedError {
    case operation(String, OSStatus)
    case unsupportedVersion(Int)

    var errorDescription: String? {
        switch self {
        case .operation(let operation, let status):
            "Keychain \(operation) failed with OSStatus \(status)"
        case .unsupportedVersion(let version):
            "Unsupported Keychain vault version \(version)"
        }
    }
}
