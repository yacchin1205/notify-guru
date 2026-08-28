import Foundation

enum WidgetSnapshotBuilder {
    static func make(from sessions: [SessionRecord]) -> WidgetSnapshot {
        WidgetSnapshot(sessions: sessions.map(makeSession))
    }

    private static func makeSession(_ session: SessionRecord) -> WidgetSessionSnapshot {
        let summary: String
        let itemKind: WidgetItemKind
        let updatedAt: Int64

        if let request = session.request {
            summary = request.prompt
            itemKind = .request
            updatedAt = request.createdAt ?? session.updatedAt ?? 0
        } else if let notification = session.notifications.last {
            summary = notification.message
            itemKind = .notification
            updatedAt = notification.createdAt ?? session.updatedAt ?? 0
        } else {
            summary = session.status
            itemKind = .status
            updatedAt = session.updatedAt ?? 0
        }

        return WidgetSessionSnapshot(
            id: session.sessionID,
            title: session.title,
            summary: summary,
            itemKind: itemKind,
            color: session.color,
            unresolvedCount: session.unresolvedCount,
            updatedAt: updatedAt,
            expiresAt: session.expiresAt
        )
    }
}
