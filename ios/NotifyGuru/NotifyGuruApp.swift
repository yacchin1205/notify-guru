import SwiftUI

@main
struct NotifyGuruApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(model)
                .onOpenURL { url in
                    Task { await model.openUniversalLink(url) }
                }
        }
    }
}
