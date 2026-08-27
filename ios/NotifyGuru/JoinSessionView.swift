import AVFoundation
import SwiftUI

struct JoinSessionView: View {
    @EnvironmentObject private var model: AppModel
    @Binding var isPresented: Bool
    @State private var cameraAuthorization = AVCaptureDevice.authorizationStatus(for: .video)
    @State private var pairingLink = ""
    @State private var joining = false
    @State private var scanGeneration = 0

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
                Text("Camera access is used only to scan a session QR code or a QR code for adding a device to a group.")
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
        guard !joining else { return }
        Task { await join(value) }
    }

    private func join(_ value: String) async {
        guard !joining else { return }
        joining = true
        let joined = await model.join(link: value)
        joining = false
        if joined {
            isPresented = false
        } else {
            scanGeneration += 1
        }
    }
}
