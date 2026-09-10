import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

#if os(iOS)
final class ShareViewController: UIViewController {
    override func viewDidLoad() {
        super.viewDidLoad()
        let controller = UIHostingController(rootView: ShareView(context: extensionContext!))
        addChild(controller)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(controller.view)
        NSLayoutConstraint.activate([
            controller.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            controller.view.topAnchor.constraint(equalTo: view.topAnchor),
            controller.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        controller.didMove(toParent: self)
    }
}
#else
final class ShareViewController: NSViewController {
    override func loadView() { view = NSView(frame: NSRect(x: 0, y: 0, width: 480, height: 520)) }
    override func viewDidLoad() {
        super.viewDidLoad()
        let controller = NSHostingController(rootView: ShareView(context: extensionContext!))
        addChild(controller)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(controller.view)
        NSLayoutConstraint.activate([
            controller.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            controller.view.topAnchor.constraint(equalTo: view.topAnchor),
            controller.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }
}
#endif

private struct SharedImage: Identifiable {
    let id = UUID()
    var photo: PreparedPhoto?
    var error: String?
}

private struct ShareView: View {
    let context: NSExtensionContext
    @State private var vault: Vault?
    @State private var destinations: [SessionRecord] = []
    @State private var destination = ""
    @State private var images: [SharedImage] = []
    @State private var message = ""
    @State private var loading = true
    @State private var sending = false
    @State private var resultUnknown = false
    @State private var error: String?
    @State private var preview: SharedImage?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Button("Cancel") { context.cancelRequest(withError: CocoaError(.userCancelled)) }
                    .accessibilityIdentifier("share-cancel")
                Spacer()
                Text("notify.guru").font(.headline)
                Spacer()
                Button("Send") { Task { await send() } }
                .disabled(loading || sending || resultUnknown || destination.isEmpty || (images.isEmpty && message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty) || images.count > 5 || images.contains { $0.photo == nil })
            }
            Picker("Send to", selection: $destination) {
                Text("Choose a session").tag("")
                ForEach(destinations) { session in
                    Label {
                        Text(session.title)
                    } icon: {
                        Image(systemName: "circle.fill")
                            .symbolRenderingMode(.palette)
                            .foregroundStyle(session.color.flatMap(Color.init(hex:)) ?? .secondary)
                    }
                    .tag(session.sessionID)
                }
            }
            .accessibilityIdentifier("share-destination")
            if let session = destinations.first(where: { $0.sessionID == destination }) {
                Text(session.status).font(.caption).foregroundStyle(.secondary).lineLimit(3)
            }
            ScrollView(.horizontal) {
                HStack(alignment: .top) {
                    ForEach(Array(images.enumerated()), id: \.element.id) { index, item in
                        VStack {
                            Text("Photo \(index + 1)")
                            if let photo = item.photo {
                                Button { preview = item } label: { photoImage(photo).frame(width: 100, height: 100) }
                                    .buttonStyle(.plain)
                            } else if let error = item.error {
                                Text(error).font(.caption).frame(width: 120)
                            } else { ProgressView() }
                            Button("Remove photo \(index + 1)", role: .destructive) { images.remove(at: index) }
                                .disabled(loading || sending)
                        }
                    }
                }
            }
            Text("Message (optional)")
            TextEditor(text: $message)
#if os(macOS)
                .font(.body)
#endif
                .frame(minHeight: 120)
                .accessibilityIdentifier("share-message")
            if loading || sending { ProgressView(loading ? "Preparing images" : "Sending") }
            if let error { Text(error).foregroundStyle(.red).accessibilityIdentifier("share-error") }
        }
        .padding()
        .task { await load() }
        .sheet(item: $preview) { item in
            VStack {
                if let photo = item.photo { photoImage(photo) }
                Button("Close") { preview = nil }
            }.padding()
        }
    }

    private func photoImage(_ photo: PreparedPhoto) -> some View {
#if os(iOS)
        Image(uiImage: UIImage(data: photo.jpeg)!).resizable().scaledToFit()
#else
        Image(nsImage: NSImage(data: photo.jpeg)!).resizable().scaledToFit()
#endif
    }

    private func load() async {
        defer { loading = false }
        do {
            let providers = (context.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
            guard !providers.isEmpty, providers.count <= 5 else {
                throw ProtocolError.invalidResponse("Share one to five images.")
            }
            images = providers.map { _ in SharedImage() }
            for (index, provider) in providers.enumerated() {
                do { images[index].photo = try await PhotoPreparer.load(provider) }
                catch { images[index].error = error.localizedDescription }
            }
            guard let saved = try KeychainVault().load(), let group = saved.identity.group else {
                error = "Open notify.guru and join a session first."
                return
            }
            vault = saved
            destinations = saved.sessions.filter {
                $0.protocolVersion == 4 && $0.groupID == group.groupID && $0.expiresAt > Int64(Date().timeIntervalSince1970 * 1000)
            }.sorted { ($0.updatedAt ?? 0) > ($1.updatedAt ?? 0) }
            if destinations.isEmpty { error = "Open notify.guru and join a session first." }
            if destinations.count == 1 { destination = destinations[0].sessionID }
        } catch { self.error = error.localizedDescription }
    }

    private func send() async {
        sending = true
        error = nil
        do {
            guard let vault, let group = vault.identity.group,
                  let session = destinations.first(where: { $0.sessionID == destination }),
                  let key = group.keys.values.max(by: { $0.timestamp < $1.timestamp }) else {
                throw ProtocolError.invalidResponse("Open notify.guru to prepare this session before sharing.")
            }
            try await APIClient().sendFeedback(
                session: session, identity: vault.identity, key: key, message: message,
                photos: images.compactMap(\.photo)
            )
            context.completeRequest(returningItems: nil)
        } catch {
            self.error = error.localizedDescription
            resultUnknown = error is FeedbackResultUnknown
            sending = false
        }
    }
}

private extension Color {
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
