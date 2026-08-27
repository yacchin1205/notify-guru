import Foundation
import Security

struct KeychainVault {
    private let service = "guru.notify.app"
    private let account = "vault"

    func load() throws -> Vault? {
        let query = key.merging([
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]) { _, new in new }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw KeychainError.operation("read", status) }
        let envelope = try JSONDecoder().decode(VersionEnvelope.self, from: data)
        guard envelope.version == 3 else { throw KeychainError.unsupportedVersion(envelope.version) }
        return try JSONDecoder().decode(Vault.self, from: data)
    }

    func save(_ vault: Vault) throws {
        guard vault.version == 3 else { throw KeychainError.unsupportedVersion(vault.version) }
        let data = try JSONEncoder().encode(vault)
        let updateStatus = SecItemUpdate(key as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw KeychainError.operation("update", updateStatus) }
        var addition = key
        addition[kSecValueData as String] = data
        addition[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(addition as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError.operation("create", status) }
    }

    func remove() throws {
        let status = SecItemDelete(key as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw KeychainError.operation("delete", status) }
    }

    private var key: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }
}

private struct VersionEnvelope: Decodable { let version: Int }

enum KeychainError: LocalizedError {
    case operation(String, OSStatus)
    case unsupportedVersion(Int)

    var errorDescription: String? {
        switch self {
        case .operation(let operation, let status): "Keychain \(operation) failed with OSStatus \(status)"
        case .unsupportedVersion(let version): "Unsupported Keychain vault version \(version)"
        }
    }
}
