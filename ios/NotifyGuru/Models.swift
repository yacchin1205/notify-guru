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
    let protocolVersion: Int
    let sessionID: String
    let creatorPublicKey: String
    let expiresAt: Int64

    enum CodingKeys: String, CodingKey {
        case sessionID = "sessionId"
        case protocolVersion, creatorPublicKey, expiresAt
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
    var createdAt: Int64? = nil
    var serverItemID: String? = nil
}

struct SessionNotification: Codable, Equatable, Identifiable {
    let id: String
    let message: String
    var createdAt: Int64? = nil
    var serverItemID: String? = nil
}

struct PreparedPhoto: Equatable {
    let jpeg: Data
    let width: Int
    let height: Int
}

struct SessionRecord: Equatable, Identifiable {
    var id: String { sessionID }
    let protocolVersion: Int
    let sessionID: String
    let groupID: String
    let creatorPublicKey: String
    var keys: [String: Data]
    var cursor: Int64
    var title: String
    var status: String
    var notifications: [SessionNotification]
    var request: SessionRequest?
    var requestKeyTimestamp: Int64?
    var color: String?
    var updatedAt: Int64?
    var expiresAt: Int64
    var attention: Bool = false

    var unresolvedCount: Int { notifications.count + (request == nil ? 0 : 1) }
    var unresolvedAccessibilityLabel: String {
        "\(unresolvedCount) unresolved \(unresolvedCount == 1 ? "item" : "items")"
    }
}

extension Collection where Element == SessionRecord {
    var unresolvedCount: Int { reduce(0) { $0 + $1.unresolvedCount } }
}

enum RelativeTime {
    static func label(timestampMilliseconds: Int64, now: Date = Date()) -> String {
        let elapsed = max(0, Int(now.timeIntervalSince1970 - Double(timestampMilliseconds) / 1_000))
        if elapsed < 60 { return "\(elapsed)s ago" }
        if elapsed < 3_600 { return "\(elapsed / 60)m ago" }
        if elapsed < 86_400 { return "\(elapsed / 3_600)h ago" }
        return "\(elapsed / 86_400)d ago"
    }
}

extension SessionRecord: Codable {
    private enum CodingKeys: String, CodingKey {
        case protocolVersion, sessionID, groupID, creatorPublicKey, keys, cursor, title, status
        case notification, notifications, request, requestKeyTimestamp, color, updatedAt, expiresAt, attention
    }

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        protocolVersion = try values.decode(Int.self, forKey: .protocolVersion)
        sessionID = try values.decode(String.self, forKey: .sessionID)
        groupID = try values.decode(String.self, forKey: .groupID)
        creatorPublicKey = try values.decode(String.self, forKey: .creatorPublicKey)
        keys = try values.decode([String: Data].self, forKey: .keys)
        cursor = try values.decode(Int64.self, forKey: .cursor)
        title = try values.decode(String.self, forKey: .title)
        status = try values.decode(String.self, forKey: .status)
        if values.contains(.notifications) {
            notifications = try values.decode([SessionNotification].self, forKey: .notifications)
        } else {
            let previous = try values.decode(String.self, forKey: .notification)
            notifications = previous.isEmpty ? [] : [SessionNotification(id: "legacy:\(sessionID)", message: previous)]
        }
        request = try values.decodeIfPresent(SessionRequest.self, forKey: .request)
        requestKeyTimestamp = try values.decodeIfPresent(Int64.self, forKey: .requestKeyTimestamp)
        color = try values.decodeIfPresent(String.self, forKey: .color)
        updatedAt = try values.decodeIfPresent(Int64.self, forKey: .updatedAt)
        expiresAt = try values.decode(Int64.self, forKey: .expiresAt)
        attention = try values.decodeIfPresent(Bool.self, forKey: .attention) ?? false
    }

    func encode(to encoder: Encoder) throws {
        var values = encoder.container(keyedBy: CodingKeys.self)
        try values.encode(protocolVersion, forKey: .protocolVersion)
        try values.encode(sessionID, forKey: .sessionID)
        try values.encode(groupID, forKey: .groupID)
        try values.encode(creatorPublicKey, forKey: .creatorPublicKey)
        try values.encode(keys, forKey: .keys)
        try values.encode(cursor, forKey: .cursor)
        try values.encode(title, forKey: .title)
        try values.encode(status, forKey: .status)
        try values.encode(notifications, forKey: .notifications)
        try values.encodeIfPresent(request, forKey: .request)
        try values.encodeIfPresent(requestKeyTimestamp, forKey: .requestKeyTimestamp)
        try values.encodeIfPresent(color, forKey: .color)
        try values.encodeIfPresent(updatedAt, forKey: .updatedAt)
        try values.encode(expiresAt, forKey: .expiresAt)
        try values.encode(attention, forKey: .attention)
    }
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
    case notification(id: String, title: String, message: String, color: String)
    case status(title: String, value: String, color: String)
    case request(title: String, value: SessionRequest, color: String)
    case closeRequest(title: String, requestID: String, color: String)
    case color(title: String, value: String)
}
