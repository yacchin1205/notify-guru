import Combine
import WidgetKit

@MainActor
final class WidgetSnapshotCoordinator {
    private let model: AppModel
    private var store: WidgetSnapshotStore?
    private var subscription: AnyCancellable?

    init(model: AppModel) {
        self.model = model
        subscription = model.$sessions
            .combineLatest(model.$isReady)
            .compactMap { sessions, isReady in isReady ? sessions : nil }
            .removeDuplicates()
            .sink { [weak self] sessions in self?.publish(sessions) }
    }

    private func publish(_ sessions: [SessionRecord]) {
        do {
            let store = try snapshotStore()
            if try store.saveIfChanged(WidgetSnapshotBuilder.make(from: sessions)) {
                WidgetCenter.shared.reloadTimelines(ofKind: WidgetSnapshotConfiguration.kind)
            }
        } catch {
            model.errorMessage = error.localizedDescription
        }
    }

    private func snapshotStore() throws -> WidgetSnapshotStore {
        if let store { return store }
        let created = try WidgetSnapshotStore()
        store = created
        return created
    }
}
