import Foundation

struct GroupKey: Codable, Equatable {
    let timestamp: Int64
    let publicKey: String
    let privateKey: Data
}

struct DeviceGroup: Codable, Equatable {
    let groupID: String
    var keys: [String: GroupKey]
}

struct DeviceRequestRecord: Codable, Equatable {
    let requestID: String
    let expiresAt: Int64
}

struct DeviceIdentity: Codable, Equatable {
    var deviceID: String
    let accessToken: String
    let encryptionPrivateKey: Data
    let signingPrivateKey: Data
    var group: DeviceGroup?
}

struct GroupDevice: Codable, Equatable, Identifiable {
    var id: String { deviceID }
    let deviceID: String
    let encryptionPublicKey: String
    let addedAt: Int64

    enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case encryptionPublicKey, addedAt
    }
}

struct GroupKeyRecord: Codable, Equatable {
    let timestamp: Int64
    let publicKey: String
    let recreated: Bool
    let members: [String]
}

struct KeyPackage: Codable, Equatable {
    let timestamp: Int64?
    let deviceID: String
    let ephemeralPublicKey: String
    let nonce: String
    let ciphertext: String

    enum CodingKeys: String, CodingKey {
        case timestamp
        case deviceID = "deviceId"
        case ephemeralPublicKey, nonce, ciphertext
    }
}

struct GroupSessionResult: Codable, Equatable {
    let sessionID: String
    let creatorPublicKey: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case sessionID = "sessionId"
        case creatorPublicKey, expiresAt
    }
}

struct DeviceGroupStateResult: Codable, Equatable {
    let groupID: String
    let members: [GroupDevice]
    let keys: [GroupKeyRecord]
    let packages: [KeyPackage]
    let sessions: [GroupSessionResult]

    enum CodingKeys: String, CodingKey {
        case groupID = "groupId"
        case members, keys, packages, sessions
    }
}

enum GroupKeyPolicy {
    static func selectUsableKey(_ state: DeviceGroupStateResult) -> GroupKeyRecord? {
        let active = Set(state.members.map(\.deviceID))
        let cutoff = state.keys.last(where: \.recreated)?.timestamp ?? 0
        return state.keys.reversed().first { $0.timestamp >= cutoff && $0.members.allSatisfy(active.contains) }
    }

    static func latestKeyMatchesMembers(_ state: DeviceGroupStateResult) -> Bool {
        guard let latest = state.keys.last else { return false }
        return latest.members.sorted() == state.members.map(\.deviceID).sorted()
    }

    static func nextKeyIsRecreated(_ state: DeviceGroupStateResult) -> Bool {
        guard let latest = state.keys.last else { return true }
        let active = Set(state.members.map(\.deviceID))
        return latest.members.contains { !active.contains($0) }
    }
}

struct SessionChoice: Codable, Equatable, Identifiable {
    let id: String
    let label: String
}

struct SessionRequest: Codable, Equatable {
    let id: String
    let prompt: String
    let options: [SessionChoice]
}

struct SessionRecord: Codable, Equatable, Identifiable {
    var id: String { sessionID }
    let protocolVersion: Int
    let sessionID: String
    let groupID: String
    let creatorPublicKey: String
    var keys: [String: Data]
    var cursor: Int64
    var title: String
    var status: String
    var notification: String
    var request: SessionRequest?
    var requestKeyTimestamp: Int64?
    var expiresAt: Int64
}

struct Vault: Codable, Equatable {
    let version: Int
    var identity: DeviceIdentity
    var sessions: [SessionRecord]
}

enum ConnectionState: Equatable {
    case preparing, syncing, current, failed

    var label: String {
        switch self {
        case .preparing: "Preparing"
        case .syncing: "Syncing"
        case .current: "Current"
        case .failed: "Sync error"
        }
    }
}

enum SessionEvent {
    case notification(title: String, message: String)
    case status(title: String, value: String)
    case request(title: String, value: SessionRequest)
}
