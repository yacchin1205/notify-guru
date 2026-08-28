import SwiftUI

@main
struct NotifyGuruApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onChange(of: model.sessions.unresolvedCount, initial: true) { _, count in
                    PushCoordinator.shared.setDesiredBadgeCount(count)
                }
                .onOpenURL { url in
                    Task { await model.openUniversalLink(url) }
                }
        }
    }
}
