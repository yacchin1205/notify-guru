import SwiftUI
import OSLog

@main
struct NotifyGuruApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()
    private let linkLogger = Logger(subsystem: "guru.notify.app", category: "LinkReception")

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .preferredColorScheme(uiTestColorScheme)
                .onChange(of: model.sessions.unresolvedCount, initial: true) { _, count in
                    PushCoordinator.shared.setDesiredBadgeCount(count)
                }
                .onOpenURL { url in
                    linkLogger.info("Received link through onOpenURL")
                    Task { await model.openUniversalLink(url) }
                }
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                    linkLogger.info("Received browsing activity through onContinueUserActivity")
                    guard let url = activity.webpageURL else {
                        model.reportError("The browsing activity did not contain a URL. Session joining was not started.")
                        return
                    }
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
