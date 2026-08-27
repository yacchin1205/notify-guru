import Foundation

struct DeviceIdentity: Codable, Equatable {
    let groupID: String
    let privateKey: Data
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

    let sessionID: String
    let groupID: String
    let groupAccessToken: String
    let sharedKey: Data
    var cursor: Int64
    var title: String
    var status: String
    var notification: String
    var request: SessionRequest?
    var expiresAt: Int64
}

struct Vault: Codable, Equatable {
    let version: Int
    let identity: DeviceIdentity
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
