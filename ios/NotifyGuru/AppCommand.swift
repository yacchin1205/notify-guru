import Foundation

enum SynchronizationChange: Equatable {
    case deviceAdded
    case deviceRequestExpired
    case deviceRemoved
}

struct AppCommandState {
    let vault: Vault
    let groupState: DeviceGroupStateResult?
    let pendingDeviceRequest: DeviceRequestRecord?
}

struct AppCommandResult {
    let nextState: AppCommandState
    let changes: [SynchronizationChange]
}

@MainActor
protocol AppCommandStateOwner: AnyObject {
    func commandState() throws -> AppCommandState
    func commit(_ nextState: AppCommandState)
}

enum AppCommand: Codable, Equatable {
    case synchronize

    case joinSession(groupID: String, pairingURL: String)
    case approveDeviceAddition(groupID: String, requestURL: String)
    case prepareDeviceGroupJoin(groupID: String, discardSavedSessions: Bool)
    case removeDevice(groupID: String, deviceID: String)
    case leaveDeviceGroup(groupID: String)

    case respond(sessionID: String, requestID: String, optionID: String)
    case dismissRequest(sessionID: String, requestID: String)
    case dismissNotification(sessionID: String, notificationID: String)
    case sendFeedback(sessionID: String, message: String, photos: [PreparedPhoto])
    case setAttention(sessionID: String, enabled: Bool)

    case registerPushToken(token: String, environment: PushEnvironment)
}
