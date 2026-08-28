import UIKit
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

    private static let authorizationOptions: UNAuthorizationOptions = [.alert, .badge, .sound]

    var onToken: ((String, PushEnvironment) -> Void)?
    var onFailure: ((Error) -> Void)?
    private var desiredBadgeCount = 0

    private init() {}

    func enable() async throws -> Bool {
        let center = UNUserNotificationCenter.current()
        let authorized = try await center.requestAuthorization(options: Self.authorizationOptions)
        if authorized {
            UIApplication.shared.registerForRemoteNotifications()
            guard await center.notificationSettings().badgeSetting == .enabled else {
                throw PushError.badgesDisabled
            }
            try await applyDesiredBadgeCount(center: center)
        }
        return authorized
    }

    func resumeIfAuthorized() async {
        let center = UNUserNotificationCenter.current()
        var settings = await center.notificationSettings()
        switch settings.authorizationStatus {
        case .authorized, .provisional, .ephemeral:
            do {
                _ = try await center.requestAuthorization(options: Self.authorizationOptions)
                settings = await center.notificationSettings()
            } catch {
                onFailure?(error)
                return
            }
            UIApplication.shared.registerForRemoteNotifications()
            guard settings.badgeSetting == .enabled else {
                onFailure?(PushError.badgesDisabled)
                return
            }
            do { try await applyDesiredBadgeCount(center: center) }
            catch { onFailure?(error) }
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

    func setDesiredBadgeCount(_ count: Int) {
        precondition(count >= 0, "Badge count must not be negative")
        desiredBadgeCount = count
        Task {
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard settings.badgeSetting == .enabled else { return }
            switch settings.authorizationStatus {
            case .authorized, .provisional, .ephemeral:
                break
            case .notDetermined, .denied:
                return
            @unknown default:
                onFailure?(PushError.unknownAuthorizationStatus)
                return
            }
            do { try await center.setBadgeCount(desiredBadgeCount) }
            catch { onFailure?(error) }
        }
    }

    private func applyDesiredBadgeCount(center: UNUserNotificationCenter) async throws {
        try await center.setBadgeCount(desiredBadgeCount)
    }
}

enum PushError: LocalizedError {
    case badgesDisabled
    case unknownAuthorizationStatus

    var errorDescription: String? {
        switch self {
        case .badgesDisabled:
            "App icon badges are turned off"
        case .unknownAuthorizationStatus:
            "iOS returned an unknown notification authorization status"
        }
    }
}
