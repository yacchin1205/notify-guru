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
        let vault = try JSONDecoder().decode(Vault.self, from: data)
        guard vault.version == 1 else {
            throw KeychainError.unsupportedVersion(vault.version)
        }
        return vault
    }

    func save(_ vault: Vault) throws {
        guard vault.version == 1 else {
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
