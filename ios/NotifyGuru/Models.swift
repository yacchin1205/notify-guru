import Foundation

struct GenerationKey: Codable, Equatable {
    let generation: Int64
    let publicKey: String
    let privateKey: Data
}

struct DeviceGroup: Codable, Equatable {
    let groupID: String
    var revision: Int64
    var generation: Int64
    var publicKey: String
    var generations: [String: GenerationKey]
}

struct DeviceInvitationRecord: Codable, Equatable {
    let groupID: String
    let invitationID: String
    let invitationToken: String
    let revision: Int64
    let generation: Int64
    let publicKey: String
    let expiresAt: Int64?
}

struct DeviceIdentity: Codable, Equatable {
    let deviceID: String
    let accessToken: String
    let encryptionPrivateKey: Data
    let signingPrivateKey: Data
    var group: DeviceGroup?
    var pendingInvitation: DeviceInvitationRecord?
    var invitations: [String: DeviceInvitationRecord]
}

struct GroupDevice: Codable, Equatable, Identifiable {
    var id: String { deviceID }
    let deviceID: String
    let encryptionPublicKey: String
    let signingPublicKey: String
    let addedAt: Int64

    enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case encryptionPublicKey, signingPublicKey, addedAt
    }
}

struct PendingDevice: Codable, Equatable, Identifiable {
    var id: String { invitationID }
    let invitationID: String
    let deviceID: String
    let encryptionPublicKey: String
    let signingPublicKey: String
    let createdAt: Int64
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case invitationID = "invitationId"
        case deviceID = "deviceId"
        case encryptionPublicKey, signingPublicKey, createdAt, expiresAt
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
    let groupAccessToken: String
    let sharedKey: Data
    let creatorPublicKey: String?
    var generationKeys: [String: Data]
    var cursor: Int64
    var title: String
    var status: String
    var notification: String
    var request: SessionRequest?
    var requestGeneration: Int64?
    var expiresAt: Int64
}

struct Vault: Codable, Equatable {
    let version: Int
    var identity: DeviceIdentity
    var sessions: [SessionRecord]
}

enum ConnectionState: Equatable {
    case preparing
    case syncing
    case current
    case failed

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
