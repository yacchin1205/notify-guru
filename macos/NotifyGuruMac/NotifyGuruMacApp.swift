import AppKit
import SwiftUI

@main
struct NotifyGuruMacApp: App {
    @NSApplicationDelegateAdaptor(MacAppDelegate.self) private var appDelegate
    @ObservedObject private var model = MacRuntime.shared.model

    var body: some Scene {
        MenuBarExtra {
            MacMenuBarView()
                .environmentObject(model)
        } label: {
            MacMenuBarLabel()
                .environmentObject(model)
        }
        .menuBarExtraStyle(.window)

        Window("Add Session", id: "join-session") {
            MacJoinView()
                .environmentObject(model)
        }
        .windowResizability(.contentSize)

        Window("Device Group", id: "device-group") {
            MacDeviceGroupView()
                .environmentObject(model)
        }
        .defaultSize(width: 520, height: 620)

        Window("Add Device", id: "device-addition-approval") {
            MacDeviceAdditionApprovalView()
                .environmentObject(model)
        }
        .windowResizability(.contentSize)
    }
}

private struct MacMenuBarLabel: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        let unresolvedCount = model.sessions.unresolvedCount
        HStack(spacing: 3) {
            Image(systemName: unresolvedCount == 0 ? "bell" : "bell.badge.fill")
            if unresolvedCount > 0 {
                Text("\(unresolvedCount)")
                    .monospacedDigit()
            }
        }
            .accessibilityLabel(
                unresolvedCount == 0
                    ? "notify.guru, no unresolved items"
                    : "notify.guru, \(unresolvedCount) unresolved \(unresolvedCount == 1 ? "item" : "items")"
            )
            .onChange(of: model.isDeviceAdditionApprovalPending) { _, pending in
                if pending { presentDeviceAdditionApproval() }
            }
            .onAppear {
                if model.isDeviceAdditionApprovalPending { presentDeviceAdditionApproval() }
            }
    }

    private func presentDeviceAdditionApproval() {
        NSApp.activate(ignoringOtherApps: true)
        openWindow(id: "device-addition-approval")
    }
}

private struct MacDeviceAdditionApprovalView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var approving = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Add a Device?")
                .font(.title2.weight(.semibold))
            Text("The new device will receive notifications and can respond as a member of this device group.")
                .foregroundStyle(.secondary)
            if let error = model.errorMessage {
                Text(error)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .textSelection(.enabled)
                    .accessibilityIdentifier("device-addition-error")
            }
            HStack {
                Spacer()
                Button("Cancel") {
                    model.cancelDeviceAddition()
                    dismiss()
                }
                .disabled(approving)
                Button("Add Device") {
                    approving = true
                    Task {
                        if await model.approvePendingDeviceAddition() { dismiss() }
                        approving = false
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(approving)
            }
        }
        .padding(24)
        .frame(width: 440)
        .onDisappear {
            if model.isDeviceAdditionApprovalPending { model.cancelDeviceAddition() }
        }
    }
}

@MainActor
final class MacRuntime {
    static let shared = MacRuntime()

    let model = AppModel()
    private var started = false

    private init() {}

    func start() {
        guard !started else { return }
        started = true
        Task {
            await model.start()
            await model.runSyncLoop()
        }
    }

    func open(_ url: URL) {
        start()
        Task { await model.openUniversalLink(url) }
    }
}
