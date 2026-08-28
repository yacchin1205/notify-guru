import CoreImage.CIFilterBuiltins
import SwiftUI

struct MacDeviceGroupView: View {
    @EnvironmentObject private var model: AppModel
    @State private var showingRequestConfirmation = false
    @State private var showingLeaveConfirmation = false
    @State private var removalTarget: GroupDevice?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                Text("Device Group")
                    .font(.largeTitle.weight(.semibold))

                if let error = model.errorMessage {
                    Text(error)
                        .font(.callout)
                        .foregroundStyle(.red)
                        .textSelection(.enabled)
                }

                addToGroupSection
                Divider()
                devicesSection

                if model.isSharingAcrossDevices {
                    Divider()
                    Button("Remove This Mac from the Group", role: .destructive) {
                        showingLeaveConfirmation = true
                    }
                }
            }
            .padding(28)
        }
        .confirmationDialog("Add this Mac to another group?", isPresented: $showingRequestConfirmation) {
            Button("Remove and Continue", role: .destructive) {
                Task { await model.createDeviceRequest(discardingCurrentState: true) }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This Mac will be removed from its current group, and its saved sessions will be deleted.")
        }
        .confirmationDialog("Remove this Mac from the group?", isPresented: $showingLeaveConfirmation) {
            Button("Remove from Group", role: .destructive) {
                Task { await model.leaveDeviceGroup() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This Mac will stop receiving notifications sent to this group. Its saved sessions will be deleted. Other devices are not affected.")
        }
        .confirmationDialog(
            "Remove the selected device from the group?",
            isPresented: Binding(get: { removalTarget != nil }, set: { if !$0 { removalTarget = nil } })
        ) {
            if let target = removalTarget {
                Button("Remove Device", role: .destructive) {
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
    private var addToGroupSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ADD THIS MAC TO ANOTHER GROUP")
                .font(.caption.weight(.bold))
                .tracking(1.2)
                .foregroundStyle(Color.notifyGuruAccent)

            if let link = model.deviceRequestLink {
                Text("On a device already in that group, scan this QR code.")
                    .foregroundStyle(.secondary)
                MacQRCodeView(value: link)
                    .frame(width: 240, height: 240)
                ShareLink(item: link) { Label("Share Link", systemImage: "square.and.arrow.up") }
            } else {
                Text("Create a QR code, then scan it with a device already in the group.")
                    .foregroundStyle(.secondary)
                Button("Add This Mac to Another Group") {
                    if model.deviceRequestWouldDiscardCurrentState {
                        showingRequestConfirmation = true
                    } else {
                        Task { await model.createDeviceRequest() }
                    }
                }
                .buttonStyle(.borderedProminent)
            }
        }
    }

    private var devicesSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("GROUP DEVICES")
                .font(.caption.weight(.bold))
                .tracking(1.2)
                .foregroundStyle(Color.notifyGuruAccent)

            if model.groupDevices.isEmpty {
                ProgressView("Loading devices…")
            } else {
                ForEach(model.groupDevices) { device in
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(device.deviceID == model.deviceID ? "This Mac" : "Device")
                            Text(device.deviceID.prefix(8))
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        if device.deviceID != model.deviceID {
                            Button("Remove", role: .destructive) { removalTarget = device }
                        }
                    }
                }
            }

            if let timestamp = model.currentKeyTimestamp {
                Text("Key \(Date(timeIntervalSince1970: Double(timestamp) / 1_000).formatted())")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }
}

private struct MacQRCodeView: View {
    let value: String

    var body: some View {
        Group {
            if let image = qrImage {
                Image(decorative: image, scale: 1)
                    .interpolation(.none)
                    .resizable()
                    .scaledToFit()
                    .accessibilityLabel("QR code for adding this Mac to a group")
            } else {
                ContentUnavailableView("QR Code Unavailable", systemImage: "qrcode")
            }
        }
        .padding(14)
        .background(.white, in: RoundedRectangle(cornerRadius: 12))
    }

    private var qrImage: CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(value.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        return CIContext().createCGImage(scaled, from: scaled.extent)
    }
}
