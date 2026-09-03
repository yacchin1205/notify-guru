import Foundation

struct GroupKey: Codable, Equatable {
    let timestamp: Int64
    let publicKey: String
    let privateKey: Data
    var transitionHash: String? = nil

    init(timestamp: Int64, publicKey: String, privateKey: Data, transitionHash: String? = nil) {
        self.timestamp = timestamp; self.publicKey = publicKey; self.privateKey = privateKey
        self.transitionHash = transitionHash
    }
}

struct DeviceGroup: Codable, Equatable {
    let groupID: String
    var keys: [String: GroupKey]
    var rootTransitionHash: String? = nil
    var headTransitionHash: String? = nil
    var pendingTransitionHash: String? = nil

    init(
        groupID: String, keys: [String: GroupKey], rootTransitionHash: String? = nil,
        headTransitionHash: String? = nil, pendingTransitionHash: String? = nil
    ) {
        self.groupID = groupID; self.keys = keys; self.rootTransitionHash = rootTransitionHash
        self.headTransitionHash = headTransitionHash; self.pendingTransitionHash = pendingTransitionHash
    }
}

struct DeviceRequestRecord: Codable, Equatable {
    let requestID: String
    let expiresAt: Int64
    let requestHash: String
    let authSecret: String

    init(requestID: String, expiresAt: Int64, requestHash: String = "", authSecret: String = "") {
        self.requestID = requestID; self.expiresAt = expiresAt
        self.requestHash = requestHash; self.authSecret = authSecret
    }
}

struct DeviceRequestDescriptor: Codable, Equatable {
    let requestID: String
    let deviceID: String
    let accessHash: String
    let signingPublicKey: String
    let encryptionPublicKey: String
    let protocolVersion: Int

    enum CodingKeys: String, CodingKey {
        case requestID = "requestId"
        case deviceID = "deviceId"
        case accessHash, signingPublicKey, encryptionPublicKey, protocolVersion
    }
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
    let signingPublicKey: String
    let addedAt: Int64

    init(deviceID: String, encryptionPublicKey: String, signingPublicKey: String = "", addedAt: Int64) {
        self.deviceID = deviceID; self.encryptionPublicKey = encryptionPublicKey
        self.signingPublicKey = signingPublicKey; self.addedAt = addedAt
    }

    enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case encryptionPublicKey, signingPublicKey, addedAt
    }
}

struct TransitionMember: Codable, Equatable {
    let deviceID: String
    let signingPublicKey: String
    let encryptionPublicKey: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case signingPublicKey, encryptionPublicKey
    }
}

struct TransitionPackageDigest: Codable, Equatable {
    let deviceID: String
    let sha256: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "deviceId"
        case sha256
    }
}

struct GroupKeyRecord: Codable, Equatable {
    let transitionID: String
    let previousHash: String
    let transitionHash: String
    let timestamp: Int64
    let actorDeviceID: String
    let publicKey: String
    let recreated: Bool
    let members: [TransitionMember]
    let packageDigests: [TransitionPackageDigest]
    let actorSignature: String
    let continuitySignature: String

    enum CodingKeys: String, CodingKey {
        case transitionID = "transitionId"
        case previousHash, transitionHash, timestamp
        case actorDeviceID = "actorDeviceId"
        case publicKey, recreated, members, packageDigests, actorSignature, continuitySignature
    }

    init(
        transitionID: String, previousHash: String, transitionHash: String, timestamp: Int64,
        actorDeviceID: String, publicKey: String, recreated: Bool, members: [TransitionMember],
        packageDigests: [TransitionPackageDigest], actorSignature: String, continuitySignature: String
    ) {
        self.transitionID = transitionID; self.previousHash = previousHash; self.transitionHash = transitionHash
        self.timestamp = timestamp; self.actorDeviceID = actorDeviceID; self.publicKey = publicKey
        self.recreated = recreated; self.members = members; self.packageDigests = packageDigests
        self.actorSignature = actorSignature; self.continuitySignature = continuitySignature
    }

    init(timestamp: Int64, publicKey: String, recreated: Bool, members: [String]) {
        self.init(
            transitionID: "test", previousHash: String(repeating: "0", count: 64), transitionHash: "",
            timestamp: timestamp, actorDeviceID: members.first ?? "", publicKey: publicKey, recreated: recreated,
            members: members.map { TransitionMember(deviceID: $0, signingPublicKey: "", encryptionPublicKey: "") },
            packageDigests: [], actorSignature: "", continuitySignature: ""
        )
    }
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
    let groupID: String
    let creatorPublicKey: String
    let expiresAt: Int64
    let keyTimestamp: Int64?
    let transitionHash: String?
    let actorDeviceID: String?
    let actorSignature: String?
    let continuitySignature: String?

    enum CodingKeys: String, CodingKey {
        case sessionID = "sessionId"
        case groupID = "groupId"
        case protocolVersion, creatorPublicKey, expiresAt, keyTimestamp, transitionHash
        case actorDeviceID = "actorDeviceId"
        case actorSignature, continuitySignature
    }
}

struct SignedSessionDescriptor: Codable, Equatable {
    let sessionID: String
    let groupID: String
    let protocolVersion: Int
    let creatorPublicKey: String
    let keyTimestamp: Int64
    let transitionHash: String
    let actorDeviceID: String
    let actorSignature: String
    let continuitySignature: String

    enum CodingKeys: String, CodingKey {
        case sessionID = "sessionId"; case groupID = "groupId"; case protocolVersion, creatorPublicKey, keyTimestamp, transitionHash
        case actorDeviceID = "actorDeviceId"; case actorSignature, continuitySignature
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
        needsRecreation(state) ? nil : state.keys.last
    }

    static func latestKeyMatchesMembers(_ state: DeviceGroupStateResult) -> Bool {
        guard let latest = state.keys.last else { return false }
        return latest.members.map(\.deviceID).sorted() == state.members.map(\.deviceID).sorted()
    }

    static func needsRecreation(_ state: DeviceGroupStateResult) -> Bool {
        guard state.keys.count >= 2 else { return false }
        let previous = state.keys[state.keys.count - 2]
        let head = state.keys[state.keys.count - 1]
        if head.recreated { return false }
        let current = Set(head.members.map(\.deviceID))
        return previous.members.contains { !current.contains($0.deviceID) }
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
