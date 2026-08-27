import Foundation

struct PairingLink: Equatable {
    let sessionID: String
    let pairingID: String
    let pairingToken: String
    let authSecret: String
    let creatorPublicKey: String

    init(_ value: String) throws {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              components.host == "notify.guru",
              components.path == "/join",
              components.query == nil,
              let fragment = components.fragment else {
            throw ProtocolError.invalidPairingLink("expected an https://notify.guru/join URL")
        }
        guard let fragmentComponents = URLComponents(string: "https://fragment.invalid/?\(fragment)"),
              let items = fragmentComponents.queryItems else {
            throw ProtocolError.invalidPairingLink("fragment is not a query string")
        }
        let expected = Set(["v", "s", "p", "t", "a", "k"])
        guard items.count == expected.count, Set(items.map(\.name)) == expected else {
            throw ProtocolError.invalidPairingLink("fragment fields do not match protocol version 2")
        }
        var fields: [String: String] = [:]
        for item in items {
            guard let itemValue = item.value, !itemValue.isEmpty, fields[item.name] == nil else {
                throw ProtocolError.invalidPairingLink("fragment contains an empty or duplicate field")
            }
            fields[item.name] = itemValue
        }
        guard fields["v"] == "2" else {
            throw ProtocolError.invalidPairingLink("unsupported protocol version")
        }
        let sessionID = fields["s"]!
        let pairingID = fields["p"]!
        let pairingToken = fields["t"]!
        let authSecret = fields["a"]!
        let creatorPublicKey = fields["k"]!
        try Self.requireIdentifier(sessionID, name: "session ID")
        try Self.requireIdentifier(pairingID, name: "pairing ID")
        guard try Base64URL.decode(pairingToken).count == 32 else {
            throw ProtocolError.invalidPairingLink("pairing token must contain 32 bytes")
        }
        guard try Base64URL.decode(authSecret).count == 32 else {
            throw ProtocolError.invalidPairingLink("authentication secret must contain 32 bytes")
        }
        guard try Base64URL.decode(creatorPublicKey).count == 65 else {
            throw ProtocolError.invalidPairingLink("creator public key must be an uncompressed P-256 key")
        }
        self.sessionID = sessionID
        self.pairingID = pairingID
        self.pairingToken = pairingToken
        self.authSecret = authSecret
        self.creatorPublicKey = creatorPublicKey
    }

    static func requireIdentifier(_ value: String, name: String) throws {
        guard (16...64).contains(value.count), value.utf8.allSatisfy({ byte in
            (byte >= 48 && byte <= 57) ||
                (byte >= 65 && byte <= 90) ||
                (byte >= 97 && byte <= 122) ||
                byte == 45 || byte == 95
        }) else {
            throw ProtocolError.invalidPairingLink("invalid \(name)")
        }
    }
}

struct DeviceInvitationLink: Equatable {
    let groupID: String
    let invitationID: String
    let invitationToken: String
    let revision: Int64
    let generation: Int64
    let publicKey: String

    init(_ value: String) throws {
        guard let components = URLComponents(string: value),
              components.scheme == "https",
              components.host == "notify.guru",
              components.path == "/device",
              components.query == nil,
              let fragment = components.fragment,
              let parsed = URLComponents(string: "https://fragment.invalid/?\(fragment)"),
              let items = parsed.queryItems else {
            throw ProtocolError.invalidPairingLink("expected an https://notify.guru/device URL")
        }
        let expected = Set(["v", "g", "i", "t", "r", "n", "k"])
        guard items.count == expected.count, Set(items.map(\.name)) == expected else {
            throw ProtocolError.invalidPairingLink("device invitation fields do not match protocol version 1")
        }
        var fields: [String: String] = [:]
        for item in items {
            guard let itemValue = item.value, !itemValue.isEmpty, fields[item.name] == nil else {
                throw ProtocolError.invalidPairingLink("device invitation contains an empty or duplicate field")
            }
            fields[item.name] = itemValue
        }
        guard fields["v"] == "1",
              let revision = Int64(fields["r"]!), revision > 0,
              let generation = Int64(fields["n"]!), generation > 0 else {
            throw ProtocolError.invalidPairingLink("invalid device invitation version or generation")
        }
        try PairingLink.requireIdentifier(fields["g"]!, name: "group ID")
        try PairingLink.requireIdentifier(fields["i"]!, name: "invitation ID")
        guard try Base64URL.decode(fields["t"]!).count == 32,
              try Base64URL.decode(fields["k"]!).count == 65 else {
            throw ProtocolError.invalidPairingLink("invalid device invitation key material")
        }
        groupID = fields["g"]!
        invitationID = fields["i"]!
        invitationToken = fields["t"]!
        self.revision = revision
        self.generation = generation
        publicKey = fields["k"]!
    }
}
