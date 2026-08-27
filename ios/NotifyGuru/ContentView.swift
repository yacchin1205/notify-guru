import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingJoin = false

    var body: some View {
        NavigationStack {
            Group {
                if !model.isReady {
                    ProgressView("Preparing secure storage…")
                } else if model.sessions.isEmpty {
                    ContentUnavailableView {
                        Label("No sessions", systemImage: "link.badge.plus")
                    } description: {
                        Text("Scan the one-shot QR code shown by notifyg.")
                    } actions: {
                        Button("Join a session") { showingJoin = true }
                            .buttonStyle(.borderedProminent)
                    }
                } else {
                    ScrollView {
                        LazyVStack(spacing: 16) {
                            ForEach(model.sessions) { session in
                                SessionCard(session: session)
                            }
                        }
                        .padding()
                    }
                    .refreshable { await model.sync() }
                }
            }
            .background(Color.brandBackground.ignoresSafeArea())
            .navigationTitle("notify.guru")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Label(model.connectionState.label, systemImage: connectionSymbol)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Join", systemImage: "qrcode.viewfinder") { showingJoin = true }
                        .disabled(!model.isReady)
                }
            }
            .sheet(isPresented: $showingJoin) {
                JoinSessionView(isPresented: $showingJoin)
            }
            .alert("notify.guru error", isPresented: errorPresented) {
                Button("OK") { model.dismissError() }
            } message: {
                Text(model.errorMessage ?? "")
            }
            .task { await model.start() }
            .task(id: model.isReady) {
                guard model.isReady else { return }
                await model.runSyncLoop()
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .active else { return }
                Task {
                    await model.sync()
                    await model.resumeNotifications()
                }
            }
        }
        .tint(.brandAccent)
    }

    private var errorPresented: Binding<Bool> {
        Binding(
            get: { model.errorMessage != nil },
            set: { if !$0 { model.dismissError() } }
        )
    }

    private var connectionSymbol: String {
        switch model.connectionState {
        case .preparing: "circle.dotted"
        case .syncing: "arrow.triangle.2.circlepath"
        case .current: "checkmark.circle"
        case .failed: "exclamationmark.triangle"
        }
    }
}

private struct SessionCard: View {
    @EnvironmentObject private var model: AppModel
    let session: SessionRecord
    @State private var responding = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("SESSION")
                        .font(.caption2.weight(.bold))
                        .tracking(1.5)
                        .foregroundStyle(Color.brandAccent)
                    Text(session.title)
                        .font(.title3.weight(.semibold))
                }
                Spacer()
                Text(expiryLabel)
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }

            if !session.status.isEmpty {
                Label(session.status, systemImage: "waveform.path.ecg")
                    .font(.subheadline.weight(.medium))
            }
            if !session.notification.isEmpty {
                Text(session.notification)
                    .font(.body)
                    .textSelection(.enabled)
            }
            if let request = session.request {
                Divider()
                Text(request.prompt)
                    .font(.headline)
                ForEach(request.options) { option in
                    Button(option.label) {
                        responding = true
                        Task {
                            await model.respond(sessionID: session.sessionID, optionID: option.id)
                            responding = false
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .disabled(responding)
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .stroke(Color.primary.opacity(0.08))
        }
    }

    private var expiryLabel: String {
        let remaining = Double(session.expiresAt) / 1_000 - Date().timeIntervalSince1970
        guard remaining > 0 else { return "Checking expiry" }
        let hours = max(1, Int(ceil(remaining / 3_600)))
        return "~\(hours)h"
    }
}

private extension Color {
    static let brandBackground = Color(uiColor: .secondarySystemBackground)
    static let brandAccent = Color(red: 0.22, green: 0.70, blue: 0.92)
}
