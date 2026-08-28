import SwiftUI

@main
struct NotifyGuruApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .preferredColorScheme(uiTestColorScheme)
                .onChange(of: model.sessions.unresolvedCount, initial: true) { _, count in
                    PushCoordinator.shared.setDesiredBadgeCount(count)
                }
                .onOpenURL { url in
                    Task { await model.openUniversalLink(url) }
                }
        }
    }

    private var uiTestColorScheme: ColorScheme? {
#if DEBUG
        if ProcessInfo.processInfo.arguments.contains("-ui-test-dark-mode") { return .dark }
        if ProcessInfo.processInfo.arguments.contains("-ui-test-light-mode") { return .light }
#endif
        return nil
    }
}
