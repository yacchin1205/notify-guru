import AppKit
import SwiftUI

struct MacMenuBarView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 390)
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("notify.guru")
                    .font(.headline)
                Text(model.connectionState.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Refresh", systemImage: "arrow.clockwise") {
                Task { await model.sync() }
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.plain)
            .disabled(!model.isReady)
        }
        .padding(14)
    }

    @ViewBuilder
    private var content: some View {
        if let startupError = model.startupErrorMessage {
            MacStartupErrorView(message: startupError)
                .padding(16)
        } else if !model.isReady {
            ProgressView("Preparing secure storage…")
                .frame(maxWidth: .infinity, minHeight: 180)
        } else {
            ScrollView {
                LazyVStack(spacing: 12) {
                    if let error = model.errorMessage {
                        MacErrorBanner(message: error)
                    }
                    if let notice = model.noticeMessage {
                        MacNoticeBanner(message: notice)
                    }
                    ForEach(model.sessions) { session in
                        MacSessionCard(session: session)
                    }
                    if model.sessions.isEmpty {
                        ContentUnavailableView {
                            Label("No sessions", systemImage: "link.badge.plus")
                        } description: {
                            Text("Open or paste a one-shot notify.guru link.")
                        } actions: {
                            Button("Add Session") { openWindow(id: "join-session") }
                                .buttonStyle(.borderedProminent)
                        }
                        .frame(minHeight: 220)
                    }
                }
                .padding(12)
            }
            .frame(minHeight: 280, idealHeight: 480, maxHeight: 620)
        }
    }

    private var footer: some View {
        HStack {
            Button("Add Session") { openWindow(id: "join-session") }
                .disabled(!model.isReady)
            Button("Device Group") { openWindow(id: "device-group") }
                .disabled(!model.isReady)
            Spacer()
            Button("Quit") { NSApplication.shared.terminate(nil) }
        }
        .buttonStyle(.plain)
        .padding(14)
    }
}

private struct MacStartupErrorView: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        ContentUnavailableView {
            Label("Unable to start", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            if model.canResetLocalData {
                Button("Erase Saved Data", role: .destructive) {
                    Task { await model.resetLocalData() }
                }
            }
        }
    }
}

private struct MacErrorBanner: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Text(message)
                .font(.callout)
                .textSelection(.enabled)
                .accessibilityIdentifier("error-message")
            Spacer(minLength: 4)
            Button("Dismiss Error", systemImage: "xmark") { model.dismissError() }
                .labelStyle(.iconOnly)
                .buttonStyle(.plain)
        }
        .padding(12)
        .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct MacNoticeBanner: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.blue)
            Text(message)
                .font(.callout)
            Spacer(minLength: 4)
            Button("Dismiss Notice", systemImage: "xmark") { model.dismissNotice() }
                .labelStyle(.iconOnly)
                .buttonStyle(.plain)
        }
        .padding(12)
        .background(.blue.opacity(0.1), in: RoundedRectangle(cornerRadius: 10))
    }
}

private struct MacSessionCard: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.colorScheme) private var colorScheme
    let session: SessionRecord
    @State private var responding = false
    @State private var composingMessage = false
    @State private var message = ""
    @State private var sendingMessage = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(session.title)
                    .font(.headline)
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    if session.unresolvedCount > 0 {
                        Text("\(session.unresolvedCount)")
                            .font(.caption2.bold().monospacedDigit())
                            .foregroundStyle(.white)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.notifyGuruAccent, in: Capsule())
                            .accessibilityLabel(session.unresolvedAccessibilityLabel)
                    }
                    if let updatedAt = session.updatedAt {
                        MacRelativeTimeText(timestampMilliseconds: updatedAt)
                    }
                    Text(expiryLabel)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
            }

            if !session.status.isEmpty {
                Label(session.status, systemImage: "waveform.path.ecg")
                    .font(.subheadline.weight(.medium))
            }

            ForEach(session.notifications) { notification in
                HStack(alignment: .top, spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(notification.message)
                            .font(.callout)
                            .textSelection(.enabled)
                        if let createdAt = notification.createdAt {
                            MacRelativeTimeText(timestampMilliseconds: createdAt)
                        }
                    }
                    Spacer(minLength: 4)
                    Button("Dismiss Notification", systemImage: "xmark") {
                        Task {
                            await model.dismissNotification(sessionID: session.sessionID, notificationID: notification.id)
                        }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
            }

            if let request = session.request {
                Divider()
                HStack(alignment: .top, spacing: 10) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(request.prompt)
                            .font(.headline)
                        if let createdAt = request.createdAt {
                            MacRelativeTimeText(timestampMilliseconds: createdAt)
                        }
                    }
                    Spacer(minLength: 4)
                    Button("Dismiss Request", systemImage: "xmark") {
                        responding = true
                        Task {
                            await model.dismissRequest(sessionID: session.sessionID)
                            responding = false
                        }
                    }
                    .labelStyle(.iconOnly)
                    .buttonStyle(.plain)
                    .disabled(responding)
                }
                HStack {
                    ForEach(request.options) { option in
                        Button(option.label) {
                            responding = true
                            Task {
                                await model.respond(sessionID: session.sessionID, optionID: option.id)
                                responding = false
                            }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(responding)
                    }
                }
            }

            if composingMessage {
                HStack {
                    TextField("Message", text: $message)
                        .textFieldStyle(.roundedBorder)
                        .onSubmit { sendMessage() }
                    Button("Send") { sendMessage() }
                        .disabled(sendingMessage || message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    Button("Cancel") {
                        composingMessage = false
                        message = ""
                    }
                }
            } else {
                HStack {
                    Spacer()
                    Button("Send a Message", systemImage: "bubble.left") { composingMessage = true }
                        .labelStyle(.iconOnly)
                        .accessibilityLabel("Send a Message")
                }
            }
        }
        .padding(14)
        .background(panelColor.opacity(colorScheme == .dark ? 0.35 : 0.72), in: RoundedRectangle(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(Color.primary.opacity(0.08))
        }
    }

    private func sendMessage() {
        guard !sendingMessage else { return }
        sendingMessage = true
        Task {
            if await model.sendFeedback(sessionID: session.sessionID, message: message) {
                composingMessage = false
                message = ""
            }
            sendingMessage = false
        }
    }

    private var panelColor: Color {
        session.color.flatMap(Color.init(hex:)) ?? Color(nsColor: .controlBackgroundColor)
    }

    private var expiryLabel: String {
        let remaining = Double(session.expiresAt) / 1_000 - Date().timeIntervalSince1970
        guard remaining > 0 else { return "Checking expiry" }
        return "~\(max(1, Int(ceil(remaining / 3_600))))h"
    }
}

private struct MacRelativeTimeText: View {
    let timestampMilliseconds: Int64

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let label = RelativeTime.label(timestampMilliseconds: timestampMilliseconds, now: context.date)
            Text(label)
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .accessibilityLabel(label)
        }
    }
}

extension Color {
    static let notifyGuruAccent = Color(red: 0.22, green: 0.70, blue: 0.92)

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
