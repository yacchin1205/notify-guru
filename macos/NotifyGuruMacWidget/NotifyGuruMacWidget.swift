import SwiftUI
import WidgetKit

@main
struct NotifyGuruMacWidgetBundle: WidgetBundle {
    var body: some Widget {
        NotifyGuruWidget()
    }
}

struct NotifyGuruWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: WidgetSnapshotConfiguration.kind, provider: NotifyGuruTimelineProvider()) { entry in
            NotifyGuruWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
                .privacySensitive()
                .widgetURL(URL(string: "notifyguru://sessions")!)
        }
        .configurationDisplayName("notify.guru Sessions")
        .description("See current sessions and unresolved items.")
        .supportedFamilies([.systemMedium, .systemLarge])
    }
}

struct NotifyGuruWidgetEntry: TimelineEntry {
    let date: Date
    let snapshot: WidgetSnapshot?
    let errorMessage: String?
}

struct NotifyGuruTimelineProvider: TimelineProvider {
    func placeholder(in context: Context) -> NotifyGuruWidgetEntry {
        NotifyGuruWidgetEntry(date: .now, snapshot: .preview, errorMessage: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (NotifyGuruWidgetEntry) -> Void) {
        completion(context.isPreview ? placeholder(in: context) : loadEntry(at: .now))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<NotifyGuruWidgetEntry>) -> Void) {
        let now = Date()
        completion(Timeline(entries: [loadEntry(at: now)], policy: .after(now.addingTimeInterval(300))))
    }

    private func loadEntry(at date: Date) -> NotifyGuruWidgetEntry {
        do {
            return NotifyGuruWidgetEntry(date: date, snapshot: try WidgetSnapshotStore().load() ?? WidgetSnapshot(sessions: []), errorMessage: nil)
        } catch {
            return NotifyGuruWidgetEntry(date: date, snapshot: nil, errorMessage: error.localizedDescription)
        }
    }
}

private struct NotifyGuruWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: NotifyGuruWidgetEntry

    var body: some View {
        if let errorMessage = entry.errorMessage {
            ContentUnavailableView {
                Label("Widget unavailable", systemImage: "exclamationmark.triangle")
            } description: {
                Text(errorMessage)
            }
        } else if let snapshot = entry.snapshot {
            let sessions = snapshot.activeSessions(at: entry.date)
            VStack(alignment: .leading, spacing: 10) {
                header(unresolvedCount: sessions.reduce(0) { $0 + $1.unresolvedCount })
                if sessions.isEmpty {
                    ContentUnavailableView {
                        Label("No sessions", systemImage: "bell")
                    } description: {
                        Text("Open notify.guru to connect a session.")
                    }
                } else {
                    ForEach(sessions.prefix(family == .systemLarge ? 4 : 2)) { session in
                        WidgetSessionRow(session: session)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding()
        }
    }

    private func header(unresolvedCount: Int) -> some View {
        HStack {
            Label("notify.guru", systemImage: unresolvedCount == 0 ? "bell" : "bell.badge.fill")
                .font(.headline)
            Spacer()
            if unresolvedCount > 0 {
                Text("\(unresolvedCount)")
                    .font(.caption.bold().monospacedDigit())
                    .foregroundStyle(.white)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(.cyan, in: Capsule())
                    .accessibilityLabel("\(unresolvedCount) unresolved items")
            }
        }
    }
}

private struct WidgetSessionRow: View {
    let session: WidgetSessionSnapshot

    var body: some View {
        HStack(spacing: 10) {
            RoundedRectangle(cornerRadius: 3)
                .fill(session.color.flatMap(Color.init(hex:)) ?? .secondary)
                .frame(width: 5)
            VStack(alignment: .leading, spacing: 3) {
                HStack {
                    Text(session.title)
                        .font(.subheadline.weight(.semibold))
                        .lineLimit(1)
                    Spacer()
                    if session.unresolvedCount > 0 {
                        Text("\(session.unresolvedCount)")
                            .font(.caption2.bold().monospacedDigit())
                    }
                }
                Label(session.summary, systemImage: session.itemKind.symbol)
                    .font(.caption)
                    .lineLimit(1)
                Text(Date(timeIntervalSince1970: Double(session.updatedAt) / 1_000), style: .relative)
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background((session.color.flatMap(Color.init(hex:)) ?? .secondary).opacity(0.16), in: RoundedRectangle(cornerRadius: 10))
    }
}

private extension WidgetItemKind {
    var symbol: String {
        switch self {
        case .notification: "bell.fill"
        case .request: "questionmark.bubble.fill"
        case .status: "waveform.path.ecg"
        }
    }
}

private extension Color {
    init?(hex: String) {
        guard hex.range(of: #"^#[0-9a-fA-F]{6}$"#, options: .regularExpression) != nil,
              let value = UInt64(hex.dropFirst(), radix: 16) else { return nil }
        self.init(
            red: Double((value >> 16) & 0xff) / 255,
            green: Double((value >> 8) & 0xff) / 255,
            blue: Double(value & 0xff) / 255
        )
    }
}

private extension WidgetSnapshot {
    static let preview = WidgetSnapshot(sessions: [
        WidgetSessionSnapshot(
            id: "preview-request", title: "Release review", summary: "Deploy this build?", itemKind: .request,
            color: "#f2d7ee", unresolvedCount: 1,
            updatedAt: Int64(Date().addingTimeInterval(-120).timeIntervalSince1970 * 1_000),
            expiresAt: Int64(Date().addingTimeInterval(86_400).timeIntervalSince1970 * 1_000)
        ),
        WidgetSessionSnapshot(
            id: "preview-status", title: "Build pipeline", summary: "Tests passed", itemKind: .status,
            color: "#d6e4ff", unresolvedCount: 0,
            updatedAt: Int64(Date().addingTimeInterval(-600).timeIntervalSince1970 * 1_000),
            expiresAt: Int64(Date().addingTimeInterval(86_400).timeIntervalSince1970 * 1_000)
        ),
    ])
}
