import AVFoundation
import SwiftUI
import UIKit

struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onCode: onCode)
    }

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let controller = QRScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {}

    final class Coordinator: NSObject, QRScannerDelegate {
        private let onCode: (String) -> Void
        private var delivered = false

        init(onCode: @escaping (String) -> Void) {
            self.onCode = onCode
        }

        func scanner(_ scanner: QRScannerViewController, found value: String) {
            guard !delivered else { return }
            delivered = true
            onCode(value)
        }
    }
}

@MainActor
protocol QRScannerDelegate: AnyObject {
    func scanner(_ scanner: QRScannerViewController, found value: String)
}

final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: QRScannerDelegate?
    private let captureSession = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private let captureQueue = DispatchQueue(label: "guru.notify.camera")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        guard let camera = AVCaptureDevice.default(for: .video) else {
            showUnavailableMessage()
            return
        }
        do {
            let input = try AVCaptureDeviceInput(device: camera)
            guard captureSession.canAddInput(input) else {
                throw ScannerError.cannotAddCameraInput
            }
            captureSession.addInput(input)
            let output = AVCaptureMetadataOutput()
            guard captureSession.canAddOutput(output) else {
                throw ScannerError.cannotAddMetadataOutput
            }
            captureSession.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let layer = AVCaptureVideoPreviewLayer(session: captureSession)
            layer.videoGravity = .resizeAspectFill
            view.layer.addSublayer(layer)
            previewLayer = layer
        } catch {
            showUnavailableMessage(error.localizedDescription)
        }
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        guard previewLayer != nil else { return }
        captureQueue.async { [captureSession] in
            captureSession.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        guard captureSession.isRunning else { return }
        captureQueue.async { [captureSession] in
            captureSession.stopRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let value = object.stringValue else {
            return
        }
        delegate?.scanner(self, found: value)
    }

    private func showUnavailableMessage(_ detail: String = "Paste the pairing link below.") {
        let label = UILabel()
        label.translatesAutoresizingMaskIntoConstraints = false
        label.text = "Camera unavailable\n\(detail)"
        label.textAlignment = .center
        label.textColor = .white
        label.numberOfLines = 0
        view.addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24),
            label.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24),
            label.centerYAnchor.constraint(equalTo: view.centerYAnchor),
        ])
    }
}

enum ScannerError: LocalizedError {
    case cannotAddCameraInput
    case cannotAddMetadataOutput

    var errorDescription: String? {
        switch self {
        case .cannotAddCameraInput: "Camera input cannot be added to the capture session"
        case .cannotAddMetadataOutput: "QR metadata output cannot be added to the capture session"
        }
    }
}
