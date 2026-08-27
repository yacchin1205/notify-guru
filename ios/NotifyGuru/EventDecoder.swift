import Foundation

enum EventDecoder {
    static func decode(_ data: Data) throws -> SessionEvent {
        let object = try JSONSerialization.jsonObject(with: data)
        guard let fields = object as? [String: Any], let type = fields["type"] as? String else {
            throw ProtocolError.invalidEvent("payload must be an object with a string type")
        }
        switch type {
        case "notify":
            try requireKeys(fields, ["id", "type", "sessionTitle", "message", "color", "createdAt"])
            try validateCommon(fields)
            return .notification(
                id: try text(fields, "id"),
                title: try text(fields, "sessionTitle"),
                message: try text(fields, "message"),
                color: try color(fields)
            )
        case "status":
            try requireKeys(fields, ["id", "type", "sessionTitle", "status", "color", "createdAt"])
            try validateCommon(fields)
            return .status(
                title: try text(fields, "sessionTitle"),
                value: try text(fields, "status"),
                color: try color(fields)
            )
        case "request":
            try requireKeys(fields, ["id", "type", "sessionTitle", "requestId", "prompt", "options", "color", "createdAt"])
            try validateCommon(fields)
            let requestID = try text(fields, "requestId")
            let prompt = try text(fields, "prompt")
            guard let rawOptions = fields["options"] as? [[String: Any]], rawOptions.count >= 2 else {
                throw ProtocolError.invalidEvent("request options must contain at least two choices")
            }
            let options = try rawOptions.map { option in
                try requireKeys(option, ["id", "label"])
                return SessionChoice(id: try text(option, "id"), label: try text(option, "label"))
            }
            return .request(
                title: try text(fields, "sessionTitle"),
                value: SessionRequest(id: requestID, prompt: prompt, options: options),
                color: try color(fields)
            )
        case "close_request":
            try requireKeys(fields, ["id", "type", "sessionTitle", "requestId", "color", "createdAt"])
            try validateCommon(fields)
            return .closeRequest(
                title: try text(fields, "sessionTitle"), requestID: try text(fields, "requestId"), color: try color(fields)
            )
        case "color":
            try requireKeys(fields, ["id", "type", "sessionTitle", "color", "createdAt"])
            try validateCommon(fields)
            return .color(title: try text(fields, "sessionTitle"), value: try color(fields))
        default:
            throw ProtocolError.invalidEvent("unsupported event type \(type)")
        }
    }

    private static func validateCommon(_ fields: [String: Any]) throws {
        _ = try text(fields, "id")
        _ = try text(fields, "sessionTitle")
        let createdAt = try text(fields, "createdAt")
        guard RFC3339.date(from: createdAt) != nil else {
            throw ProtocolError.invalidEvent("createdAt is not RFC 3339")
        }
    }

    private static func requireKeys(_ fields: [String: Any], _ expected: Set<String>) throws {
        guard Set(fields.keys) == expected else {
            throw ProtocolError.invalidEvent("payload fields do not match the protocol")
        }
    }

    private static func text(_ fields: [String: Any], _ name: String) throws -> String {
        guard let value = fields[name] as? String, !value.isEmpty else {
            throw ProtocolError.invalidEvent("\(name) must be a non-empty string")
        }
        return value
    }

    private static func color(_ fields: [String: Any]) throws -> String {
        let value = try text(fields, "color")
        guard value.range(of: #"^#[0-9a-fA-F]{6}$"#, options: .regularExpression) != nil else {
            throw ProtocolError.invalidEvent("color must be #rrggbb")
        }
        return value.lowercased()
    }
}

enum RFC3339 {
    static func string(from date: Date) -> String {
        fractional.string(from: date)
    }

    static func date(from value: String) -> Date? {
        if value.contains(".") {
            return fractional.date(from: value)
        }
        return wholeSeconds.date(from: value)
    }

    private static let fractional: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter
    }()

    private static let wholeSeconds: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter
    }()
}
