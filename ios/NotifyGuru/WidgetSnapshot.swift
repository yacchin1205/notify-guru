import Foundation

enum WidgetSnapshotConfiguration {
    static let kind = "guru.notify.app.widget.sessions"
}

enum WidgetItemKind: String, Codable, Equatable {
    case notification
    case request
    case status
}

struct WidgetSessionSnapshot: Codable, Equatable, Identifiable {
    let id: String
    let title: String
    let summary: String
    let itemKind: WidgetItemKind
    let color: String?
    let unresolvedCount: Int
    let updatedAt: Int64
    let expiresAt: Int64
}

struct WidgetSnapshot: Codable, Equatable {
    let sessions: [WidgetSessionSnapshot]

    func activeSessions(at date: Date) -> [WidgetSessionSnapshot] {
        let now = Int64(date.timeIntervalSince1970 * 1_000)
        return sessions.filter { $0.expiresAt > now }
    }
}
