import Foundation

struct WidgetSnapshotStore {
    private static let appGroupInfoKey = "NotifyGuruAppGroupIdentifier"
    private static let fileName = "widget-snapshot.json"

    private let fileURL: URL
    private let encoder: JSONEncoder
    private let decoder = JSONDecoder()

    init(bundle: Bundle = .main, fileManager: FileManager = .default) throws {
        guard let identifier = bundle.object(forInfoDictionaryKey: Self.appGroupInfoKey) as? String,
              !identifier.isEmpty else {
            throw WidgetSnapshotStoreError.missingAppGroupIdentifier
        }
        guard let directory = fileManager.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
            throw WidgetSnapshotStoreError.appGroupUnavailable(identifier)
        }
        self.init(directoryURL: directory)
    }

    init(directoryURL: URL) {
        fileURL = directoryURL.appendingPathComponent(Self.fileName, isDirectory: false)
        encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
    }

    func load() throws -> WidgetSnapshot? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        return try decoder.decode(WidgetSnapshot.self, from: Data(contentsOf: fileURL))
    }

    @discardableResult
    func saveIfChanged(_ snapshot: WidgetSnapshot) throws -> Bool {
        let data = try encoder.encode(snapshot)
        if FileManager.default.fileExists(atPath: fileURL.path), try Data(contentsOf: fileURL) == data {
            return false
        }
        try data.write(to: fileURL, options: .atomic)
        return true
    }
}

enum WidgetSnapshotStoreError: LocalizedError {
    case missingAppGroupIdentifier
    case appGroupUnavailable(String)

    var errorDescription: String? {
        switch self {
        case .missingAppGroupIdentifier:
            "The widget data group is not configured."
        case .appGroupUnavailable(let identifier):
            "The widget data group \(identifier) is unavailable."
        }
    }
}
