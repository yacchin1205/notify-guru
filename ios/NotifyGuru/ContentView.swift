import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct ContentView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingJoin = false
    @State private var showingDeviceManagement = false

    var body: some View {
        NavigationStack {
            Group {
                if let startupErrorMessage = model.startupErrorMessage {
                    StartupErrorView(message: startupErrorMessage)
                } else if !model.isReady {
                    ProgressView("Preparing secure storage…")
                } else {
                    ScrollView {
                        LazyVStack(spacing: 16) {
                            if model.isAwaitingDeviceApproval {
                                DeviceApprovalWaitingCard()
                            } else {
                                DeviceSummaryCard(showingManagement: $showingDeviceManagement)
                            }
                            ForEach(model.sessions) { session in
                                SessionCard(session: session)
                            }
                            if model.sessions.isEmpty {
                                ContentUnavailableView {
                                    Label("No sessions", systemImage: "link.badge.plus")
                                } description: {
                                    Text("Scan the one-shot QR code shown by notifyg.")
                                } actions: {
                                    Button("Scan QR code") { showingJoin = true }
                                        .buttonStyle(.borderedProminent)
                                }
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
                    Button("Scan QR code", systemImage: "qrcode.viewfinder") { showingJoin = true }
                        .disabled(!model.isReady)
                }
            }
            .sheet(isPresented: $showingJoin) {
                JoinSessionView(isPresented: $showingJoin)
            }
            .sheet(isPresented: $showingDeviceManagement) {
                DeviceManagementView(isPresented: $showingDeviceManagement)
            }
            .alert("notify.guru error", isPresented: errorPresented) {
                Button("OK") { model.dismissError() }
            } message: {
                Text(model.errorMessage ?? "")
            }
            .alert("notify.guru", isPresented: noticePresented) {
                Button("OK") { model.dismissNotice() }
            } message: {
                Text(model.noticeMessage ?? "")
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

    private var noticePresented: Binding<Bool> {
        Binding(
            get: { model.noticeMessage != nil },
            set: { if !$0 { model.dismissNotice() } }
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

private struct StartupErrorView: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        ContentUnavailableView {
            Label("Unable to start", systemImage: "exclamationmark.triangle")
        } description: {
            Text(message)
        } actions: {
            if model.canResetLocalData {
                Button("Erase saved data", role: .destructive) {
                    Task { await model.resetLocalData() }
                }
                .buttonStyle(.bordered)
            }
        }
    }
}

private struct DeviceSummaryCard: View {
    @EnvironmentObject private var model: AppModel
    @Binding var showingManagement: Bool

    var body: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 4) {
                Text("DEVICE GROUP")
                    .font(.caption2.weight(.bold))
                    .tracking(1.5)
                    .foregroundStyle(Color.brandAccent)
                Text(model.isSharingAcrossDevices ? "\(model.deviceCount) devices in this group" : "Not shared")
                    .font(.headline)
            }
            Spacer()
            Button("Manage group") { showingManagement = true }
                .buttonStyle(.bordered)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

private struct DeviceApprovalWaitingCard: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("DEVICE GROUP")
                .font(.caption2.weight(.bold))
                .tracking(1.5)
                .foregroundStyle(Color.brandAccent)
            Text("Waiting to be added to a group")
                .font(.headline)
            Text("On a device already in that group, scan this QR code.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            if let link = model.deviceRequestLink {
                InvitationQRCodeView(value: link)
                ShareLink(item: link) { Label("Share link", systemImage: "square.and.arrow.up") }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }
}

private struct DeviceManagementView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var isPresented: Bool
    @State private var showingLeaveConfirmation = false
    @State private var showingRequestConfirmation = false
    @State private var removalTarget: GroupDevice?

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    requestSection
                    Divider()
                    deviceSection
                    if model.isSharingAcrossDevices {
                        Divider()
                        Button("Remove this device from the group", role: .destructive) {
                            showingLeaveConfirmation = true
                        }
                        .buttonStyle(.bordered)
                    }
                }
                .padding()
            }
            .background(Color.brandBackground)
            .navigationTitle("Device Group")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { isPresented = false }
                }
            }
        }
        .confirmationDialog(
            "Add this device to another group?",
            isPresented: $showingRequestConfirmation,
            titleVisibility: .visible
        ) {
            Button("Remove and continue", role: .destructive) {
                Task { await model.createDeviceRequest(discardingCurrentState: true) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This device will be removed from its current group, and its saved sessions will be deleted.")
        }
        .confirmationDialog(
            "Remove this device from the group?",
            isPresented: $showingLeaveConfirmation,
            titleVisibility: .visible
        ) {
            Button("Remove from group", role: .destructive) {
                Task {
                    await model.leaveDeviceGroup()
                    if !model.isSharingAcrossDevices { isPresented = false }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This device will stop receiving notifications sent to this group. Its saved sessions will be deleted. Other devices are not affected.")
        }
        .confirmationDialog(
            "Remove the selected device from the group?",
            isPresented: Binding(
                get: { removalTarget != nil },
                set: { if !$0 { removalTarget = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let target = removalTarget {
                Button("Remove device", role: .destructive) {
                    Task {
                        await model.removeDevice(target.deviceID)
                        removalTarget = nil
                    }
                }
            }
            Button("Cancel", role: .cancel) { removalTarget = nil }
        } message: {
            Text("The selected device will stop receiving notifications sent to this group.")
        }
    }

    @ViewBuilder
    private var requestSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ADD THIS DEVICE TO ANOTHER GROUP")
                .font(.caption2.weight(.bold))
                .tracking(1.5)
                .foregroundStyle(Color.brandAccent)
            if let link = model.deviceRequestLink {
                Text("On a device already in that group, scan this QR code.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                InvitationQRCodeView(value: link)
                ShareLink(item: link) { Label("Share link", systemImage: "square.and.arrow.up") }
            } else {
                Text("Create a QR code, then scan it with a device already in the group.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Button("Add this device to another group") {
                    if model.deviceRequestWouldDiscardCurrentState { showingRequestConfirmation = true }
                    else { Task { await model.createDeviceRequest() } }
                }
                .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var deviceSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("GROUP DEVICES")
                .font(.caption2.weight(.bold))
                .tracking(1.5)
                .foregroundStyle(Color.brandAccent)
            ForEach(model.groupDevices) { device in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(device.deviceID == model.deviceID ? "This device" : "Device")
                        Text(device.deviceID.prefix(8))
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if device.deviceID != model.deviceID {
                        Button("Remove", role: .destructive) { removalTarget = device }
                            .buttonStyle(.bordered)
                    }
                }
            }
            if let timestamp = model.currentKeyTimestamp {
                Text("Key \(Date(timeIntervalSince1970: Double(timestamp) / 1_000).formatted())")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct InvitationQRCodeView: View {
    let value: String

    var body: some View {
        Group {
            if let image = InvitationQRCode.image(for: value) {
                Image(uiImage: image)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .accessibilityLabel("QR code for adding this device to a group")
            } else {
                ContentUnavailableView("QR code unavailable", systemImage: "qrcode")
            }
        }
        .padding(16)
        .background(.white, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

enum InvitationQRCode {
    static func image(for value: String) -> UIImage? {
        guard !value.isEmpty else { return nil }

        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }

        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        let context = CIContext()
        guard let image = context.createCGImage(scaled, from: scaled.extent) else { return nil }
        return UIImage(cgImage: image)
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
