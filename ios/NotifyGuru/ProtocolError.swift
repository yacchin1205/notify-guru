import Foundation

enum ProtocolError: LocalizedError {
    case invalidBase64URL
    case invalidPairingLink(String)
    case invalidResponse(String)
    case invalidEvent(String)
    case crypto(String)

    var errorDescription: String? {
        switch self {
        case .invalidBase64URL:
            "Invalid base64url value"
        case .invalidPairingLink(let message):
            "Invalid pairing link: \(message)"
        case .invalidResponse(let message):
            "Invalid server response: \(message)"
        case .invalidEvent(let message):
            "Invalid encrypted event: \(message)"
        case .crypto(let message):
            "Cryptographic operation failed: \(message)"
        }
    }
}
