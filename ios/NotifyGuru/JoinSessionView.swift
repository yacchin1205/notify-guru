import AVFoundation
import SwiftUI

struct JoinSessionView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var isPresented: Bool
    @State private var cameraAuthorization = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var pairingLink = ""
    @State private var joining = false
    @State private var scanGeneration = 0
    @State private var replacementLink: String?

    var body: some View {
        NavigationStack {
            VStack(spacing: 18) {
                cameraContent
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 20, style: .continuous))

                TextField("https://notify.guru/…#…", text: $pairingLink, axis: .vertical)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textContentType(.URL)
                    .keyboardType(.URL)
                    .lineLimit(2...4)
                    .padding(12)
                    .background(.background, in: RoundedRectangle(cornerRadius: 12))

                Button("Continue") { beginJoin(pairingLink) }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(pairingLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || joining)
            }
            .padding()
            .background(Color(uiColor: .secondarySystemBackground))
            .navigationTitle("Scan QR code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { isPresented = false }
                }
            }
        }
        .confirmationDialog(
            "Replace this device's current sessions?",
            isPresented: Binding(
                get: { replacementLink != nil },
                set: { if !$0 { replacementLink = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let value = replacementLink {
                Button("Replace and continue", role: .destructive) {
                    replacementLink = nil
                    Task { await join(value, replacingStandaloneSessions: true) }
                }
            }
            Button("Cancel", role: .cancel) {
                replacementLink = nil
                scanGeneration += 1
            }
        } message: {
            Text("The sessions and keys currently stored on this device will be removed before it starts sharing with the other devices.")
        }
    }

    @ViewBuilder
    private var cameraContent: some View {
        switch cameraAuthorization {
        case .authorized:
            QRScannerView { value in
                pairingLink = value
                beginJoin(value)
            }
            .id(scanGeneration)
        case .notDetermined:
            ContentUnavailableView {
                Label("Camera access", systemImage: "camera")
            } description: {
                Text("Camera access is used only to scan a session or device invitation QR code.")
            } actions: {
                Button("Allow camera") { requestCameraAccess() }
                    .buttonStyle(.borderedProminent)
            }
        case .denied, .restricted:
            ContentUnavailableView(
                "Camera unavailable",
                systemImage: "camera.fill",
                description: Text("Paste the pairing link below, or allow camera access in Settings.")
            )
        @unknown default:
            ContentUnavailableView("Unknown camera state", systemImage: "exclamationmark.triangle")
        }
    }

    private func requestCameraAccess() {
        AVCaptureDevice.requestAccess(for: .video) { granted in
            Task { @MainActor in
                cameraAuthorization = granted ? .authorized : .denied
            }
        }
    }

    private func beginJoin(_ value: String) {
        guard !joining, replacementLink == nil else { return }
        if model.deviceInvitationWouldReplaceSessions(value) {
            replacementLink = value
            return
        }
        Task { await join(value, replacingStandaloneSessions: false) }
    }

    private func join(_ value: String, replacingStandaloneSessions: Bool) async {
        guard !joining else { return }
        joining = true
        let joined = await model.join(link: value, replacingStandaloneSessions: replacingStandaloneSessions)
        joining = false
        if joined {
            isPresented = false
        } else {
            scanGeneration += 1
        }
    }
}
