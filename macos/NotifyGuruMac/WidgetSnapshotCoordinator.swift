import Combine
import WidgetKit

@MainActor
final class WidgetSnapshotCoordinator {
    private let model: AppModel
    private var store: WidgetSnapshotStore?
    private var subscription: AnyCancellable?

    init(model: AppModel, store: WidgetSnapshotStore? = nil) {
        self.model = model
        self.store = store
        subscription = model.objectWillChange
            .map { _ in () }
            .prepend(())
            .receive(on: RunLoop.main)
            .compactMap { [weak model] in
                guard let model, model.isReady else { return nil }
                return model.sessions
            }
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
            model.reportError(error.localizedDescription)
        }
    }

    private func snapshotStore() throws -> WidgetSnapshotStore {
        if let store { return store }
        let created = try WidgetSnapshotStore()
        store = created
        return created
    }
}
