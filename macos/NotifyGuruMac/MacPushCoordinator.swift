import AppKit
import UserNotifications

enum PushEnvironment: String, Codable {
    case sandbox
    case production

    static var current: PushEnvironment {
#if DEBUG
        .sandbox
#else
        .production
#endif
    }
}

@MainActor
final class PushCoordinator {
    static let shared = PushCoordinator()

    var onToken: ((String, PushEnvironment) -> Void)?
    var onFailure: ((Error) -> Void)?

    private init() {}

    func enable() async throws -> Bool {
        let center = UNUserNotificationCenter.current()
        let settings = await center.notificationSettings()
        let authorized: Bool
        switch settings.authorizationStatus {
        case .notDetermined:
            authorized = try await center.requestAuthorization(options: [.alert, .sound])
        case .authorized, .provisional:
            authorized = true
        case .denied:
            authorized = false
        @unknown default:
            throw PushError.unknownAuthorizationStatus
        }
        if authorized {
            NSApplication.shared.registerForRemoteNotifications()
        }
        return authorized
    }

    func resumeIfAuthorized() async {
        let settings = await UNUserNotificationCenter.current().notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional:
            NSApplication.shared.registerForRemoteNotifications()
        case .notDetermined, .denied:
            return
        @unknown default:
            onFailure?(PushError.unknownAuthorizationStatus)
        }
    }

    func received(deviceToken: Data) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        onToken?(token, .current)
    }

    func failed(_ error: Error) {
        onFailure?(error)
    }
}

enum PushError: LocalizedError {
    case unknownAuthorizationStatus

    var errorDescription: String? {
        "macOS returned an unknown notification authorization status"
    }
}
