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

                Button("Join") {
                    Task { await join(pairingLink) }
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(pairingLink.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || joining)
            }
            .padding()
            .background(Color(uiColor: .secondarySystemBackground))
            .navigationTitle("Scan a link")
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
                Task { await join(value) }
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
