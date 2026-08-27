import CryptoKit
import XCTest
@testable import NotifyGuru

final class ProtocolTests: XCTestCase {
    func testPairingLinkRequiresExactFragment() throws {
        let token = Base64URL.encode(Data(repeating: 1, count: 32))
        let secret = Base64URL.encode(Data(repeating: 2, count: 32))
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: Data(repeating: 3, count: 32))
        let publicKey = Base64URL.encode(privateKey.publicKey.x963Representation)
        let link = try PairingLink("https://notify.guru/join#v=1&s=session&p=pairing&t=\(token)&a=\(secret)&k=\(publicKey)")

        XCTAssertEqual(link.sessionID, "session")
        XCTAssertThrowsError(try PairingLink("https://notify.guru/join#v=1&s=session&p=pairing&t=\(token)&a=\(secret)&k=\(publicKey)&extra=true"))
    }

    func testPeersDeriveSameSessionKey() throws {
        let first = DeviceIdentity(groupID: "first", privateKey: Data(repeating: 3, count: 32))
        let second = DeviceIdentity(groupID: "second", privateKey: Data(repeating: 4, count: 32))

        let firstKey = try CryptoEngine.deriveSessionKey(
            identity: first,
            creatorPublicKey: try CryptoEngine.publicKey(for: second),
            sessionID: "session-id"
        )
        let secondKey = try CryptoEngine.deriveSessionKey(
            identity: second,
            creatorPublicKey: try CryptoEngine.publicKey(for: first),
            sessionID: "session-id"
        )

        XCTAssertEqual(firstKey, secondKey)
        XCTAssertEqual(try CryptoEngine.publicKey(for: first), "BFkat3HrvP1tnLkJTRBlKK3Rpp1EwsH2J_CJ7Fi5xhrfn05qvw0EXAxpOjxorXyXynK-ZN70om_s0mPdmKkngPA")
        XCTAssertEqual(Base64URL.encode(firstKey), "uaEVrcIWs4cNzciEiU3iqSyYpjF_bNrUm3lu4YXRUZA")
    }

    func testDecryptsGoEventVector() throws {
        let session = SessionRecord(
            sessionID: "session-id",
            groupID: "first",
            groupAccessToken: "unused",
            sharedKey: try Base64URL.decode("uaEVrcIWs4cNzciEiU3iqSyYpjF_bNrUm3lu4YXRUZA"),
            cursor: 0,
            title: "",
            status: "",
            notification: "",
            request: nil,
            expiresAt: 0
        )
        let envelope = EventEnvelope(
            sequence: 1,
            eventID: "event-id",
            groupID: "first",
            nonce: "BQUFBQUFBQUFBQUF",
            ciphertext: "OzZ_nSEMbRHBMJSlsDuAdnPzTFnot1-_kPLLyMolGCimmFQOP7y_PuDnxwK9X8DJj7pXPloDhoOVERbJEDqzoHkfmTMz6bX-_iXgBlJunarXseLIdfEUXc-DxfapQgI_Io4_SYhuu7RqGovKQ8uPpFn6XtONGgxPCQ",
            createdAt: 0
        )

        guard case .notification(let title, let message) = try CryptoEngine.decryptEvent(session: session, envelope: envelope) else {
            return XCTFail("Go event vector did not decode as notify")
        }
        XCTAssertEqual(title, "Build")
        XCTAssertEqual(message, "Done")
    }

    func testEventDecoderRejectsUnknownFields() throws {
        let data = Data(#"{"id":"event","type":"notify","sessionTitle":"Build","message":"Done","createdAt":"2026-08-27T00:00:00Z","extra":true}"#.utf8)
        XCTAssertThrowsError(try EventDecoder.decode(data))
    }

    func testVaultRoundTrip() throws {
        let vault = Vault(
            version: 1,
            identity: DeviceIdentity(groupID: "group", privateKey: Data(repeating: 7, count: 32)),
            sessions: []
        )
        let encoded = try JSONEncoder().encode(vault)
        XCTAssertEqual(try JSONDecoder().decode(Vault.self, from: encoded), vault)
    }
}
