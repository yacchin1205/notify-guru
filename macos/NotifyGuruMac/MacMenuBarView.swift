import AppKit
import ImageIO
import SwiftUI
import UniformTypeIdentifiers

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
        .frame(maxWidth: .infinity, minHeight: 220)
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
    @State private var preparingPhoto = false
    @State private var photo: PreparedPhoto?
    @State private var photoError: String?
    @State private var photoImportID = UUID()
    @State private var togglingAttention = false
    @FocusState private var messageFocused: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text(session.title)
                    .font(.headline)
                if session.attention {
                    Image(systemName: "eye.fill")
                        .foregroundStyle(Color.notifyGuruAccent)
                        .accessibilityLabel("Watching Status Updates")
                }
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

            if let syncError = model.sessionSyncErrors[session.sessionID] {
                Label(syncError, systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .accessibilityIdentifier("session-sync-error")
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
                VStack(alignment: .leading, spacing: 8) {
                    TextField("Message", text: $message)
                        .textFieldStyle(.roundedBorder)
                        .accessibilityIdentifier("mac-message-editor")
                        .focused($messageFocused)
                        .onSubmit { sendMessage() }
                    if let photo, let image = NSImage(data: photo.jpeg) {
                        HStack(alignment: .top, spacing: 8) {
                            Image(nsImage: image)
                                .resizable()
                                .scaledToFit()
                                .frame(width: 88, height: 88)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .accessibilityLabel("Selected image preview")
                                .accessibilityIdentifier("mac-selected-photo-preview")
                            Button("Remove Image", systemImage: "trash", role: .destructive) {
                                self.photo = nil
                                photoError = nil
                            }
                            .disabled(preparingPhoto)
                        }
                    }
                    if let photoError {
                        Text(photoError)
                            .font(.caption)
                            .foregroundStyle(.red)
                            .accessibilityIdentifier("mac-photo-preparation-error")
                    }
                    HStack {
                        if session.protocolVersion == 4 {
                            PasteButton(supportedContentTypes: [.image]) { providers in
                                importPhoto(from: providers)
                            }
                            .labelStyle(.titleAndIcon)
                            .accessibilityLabel("Paste Image")
                            .disabled(preparingPhoto)
                        }
                        if preparingPhoto {
                            ProgressView()
                                .controlSize(.small)
                                .accessibilityLabel("Preparing image")
                        }
                        Spacer()
                        Button("Send") { sendMessage() }
                            .disabled(!canSendMessage)
                        Button("Cancel") { resetComposer() }
                    }
                }
                .background {
                    if session.protocolVersion == 4 {
                        MacImagePasteShortcut {
                            guard messageFocused else { return false }
                            return importPhotoFromPasteboard()
                        }
                            .frame(width: 0, height: 0)
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
                .stroke(session.attention ? Color.notifyGuruAccent : Color.primary.opacity(0.08), lineWidth: session.attention ? 2 : 1)
        }
        .shadow(color: session.attention ? Color.notifyGuruAccent.opacity(0.55) : .clear, radius: 12)
        .onLongPressGesture { toggleAttention() }
        .contextMenu {
            Button(session.attention ? "Stop Watching Status Updates" : "Watch Status Updates") { toggleAttention() }
        }
    }

    private func toggleAttention() {
        guard !togglingAttention else { return }
        togglingAttention = true
        Task {
            _ = await model.setAttention(sessionID: session.sessionID, attention: !session.attention)
            togglingAttention = false
        }
    }

    private func sendMessage() {
        guard canSendMessage else { return }
        sendingMessage = true
        Task {
            if await model.sendFeedback(sessionID: session.sessionID, message: message, photo: photo) {
                resetComposer()
            }
            sendingMessage = false
        }
    }

    private var canSendMessage: Bool {
        !sendingMessage && !preparingPhoto &&
        (!message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || photo != nil)
    }

    private func resetComposer() {
        photoImportID = UUID()
        composingMessage = false
        messageFocused = false
        message = ""
        photo = nil
        photoError = nil
        preparingPhoto = false
    }

    private func importPhoto(from providers: [NSItemProvider]) {
        guard !preparingPhoto else { return }
        let imageProviders = providers.filter { provider in
            provider.registeredTypeIdentifiers.contains { identifier in
                UTType(identifier)?.conforms(to: .image) == true
            }
        }
        guard imageProviders.count == 1, let provider = imageProviders.first else {
            photoError = imageProviders.isEmpty
                ? "The clipboard does not contain an image."
                : "Only one image can be attached."
            return
        }
        guard let typeIdentifier = provider.registeredTypeIdentifiers.first(where: { identifier in
            UTType(identifier)?.conforms(to: .image) == true
        }) else {
            photoError = "The clipboard image format is not supported."
            return
        }

        let importID = UUID()
        photoImportID = importID
        preparingPhoto = true
        photoError = nil
        provider.loadDataRepresentation(forTypeIdentifier: typeIdentifier) { data, _ in
            guard let data else {
                completePhotoImport(nil, importID: importID)
                return
            }
            preparePhoto(data, importID: importID)
        }
    }

    /// Handles an explicit Command-V without polling or observing clipboard contents.
    /// Returning false lets AppKit continue its normal text paste behavior.
    private func importPhotoFromPasteboard() -> Bool {
        guard !preparingPhoto else { return true }
        let imageItems = (NSPasteboard.general.pasteboardItems ?? []).compactMap { item -> (NSPasteboardItem, NSPasteboard.PasteboardType)? in
            guard let type = item.types.first(where: { type in
                UTType(type.rawValue)?.conforms(to: .image) == true
            }) else { return nil }
            return (item, type)
        }
        guard !imageItems.isEmpty else { return false }
        guard imageItems.count == 1 else {
            photoError = "Only one image can be attached."
            return true
        }
        guard let data = imageItems[0].0.data(forType: imageItems[0].1) else {
            photoError = "The clipboard image format is not supported."
            return true
        }

        let importID = UUID()
        photoImportID = importID
        preparingPhoto = true
        photoError = nil
        preparePhoto(data, importID: importID)
        return true
    }

    private func preparePhoto(_ data: Data, importID: UUID) {
        DispatchQueue.global(qos: .userInitiated).async {
            completePhotoImport(MacPhotoPreparer.prepare(data), importID: importID)
        }
    }

    private func completePhotoImport(_ prepared: PreparedPhoto?, importID: UUID) {
        DispatchQueue.main.async {
            guard photoImportID == importID, composingMessage else { return }
            if let prepared {
                photo = prepared
            } else {
                photoError = "The clipboard image could not be prepared within the attachment limit."
            }
            preparingPhoto = false
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

/// A composer-scoped local key monitor. It consumes Command-V only when the
/// action accepted an image, so ordinary text paste remains AppKit's behavior.
private struct MacImagePasteShortcut: NSViewRepresentable {
    let perform: () -> Bool

    func makeNSView(context: Context) -> MonitorView {
        MonitorView(perform: perform)
    }

    func updateNSView(_ nsView: MonitorView, context: Context) {
        nsView.perform = perform
    }

    static func dismantleNSView(_ nsView: MonitorView, coordinator: ()) {
        nsView.stopMonitoring()
    }

    final class MonitorView: NSView {
        var perform: () -> Bool
        private var monitor: Any?

        init(perform: @escaping () -> Bool) {
            self.perform = perform
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) {
            fatalError("init(coder:) has not been implemented")
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil {
                stopMonitoring()
            } else {
                startMonitoring()
            }
        }

        func stopMonitoring() {
            guard let monitor else { return }
            NSEvent.removeMonitor(monitor)
            self.monitor = nil
        }

        private func startMonitoring() {
            guard monitor == nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
                let modifiers = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
                guard modifiers == .command,
                      event.charactersIgnoringModifiers?.lowercased() == "v",
                      let self,
                      self.perform() else { return event }
                return nil
            }
        }

        deinit {
            stopMonitoring()
        }
    }
}

private enum MacPhotoPreparer {
    private static let maximumInputBytes = 64 * 1024 * 1024
    private static let preferredJPEGBytes = 1024 * 1024
    private static let maximumJPEGBytes = 2 * 1024 * 1024 - 16

    static func prepare(_ data: Data) -> PreparedPhoto? {
        guard !data.isEmpty, data.count <= maximumInputBytes,
              let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
        var maximumPixelSize = 2048
        var quality = 0.82
        for attempt in 0..<10 {
            let options: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: true,
                kCGImageSourceThumbnailMaxPixelSize: maximumPixelSize,
                kCGImageSourceShouldCacheImmediately: true,
            ]
            guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, options as CFDictionary),
                  let jpeg = jpegData(image, quality: quality) else { return nil }
            if jpeg.count <= preferredJPEGBytes || (attempt == 9 && jpeg.count <= maximumJPEGBytes) {
                return PreparedPhoto(jpeg: jpeg, width: image.width, height: image.height)
            }
            if quality > 0.55 {
                quality -= 0.09
            } else {
                maximumPixelSize = max(1, Int((Double(maximumPixelSize) * 0.82).rounded()))
            }
        }
        return nil
    }

    private static func jpegData(_ image: CGImage, quality: Double) -> Data? {
        let data = NSMutableData()
        guard let destination = CGImageDestinationCreateWithData(
            data, UTType.jpeg.identifier as CFString, 1, nil
        ) else { return nil }
        CGImageDestinationAddImage(
            destination,
            image,
            [kCGImageDestinationLossyCompressionQuality: quality] as CFDictionary
        )
        guard CGImageDestinationFinalize(destination) else { return nil }
        return data as Data
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
