import Keychain_Security
import Security
import Testing

/// These never reach the keychain: a test touches no real item.
@Suite struct `Keychain.Item Tests` {
    @Test func `an item without an account searches by service alone`() {
        let query = Keychain.Item(service: "invented").query
        #expect(query[kSecAttrService as String] as? String == "invented")
        #expect(query[kSecAttrAccount as String] == nil)
    }

    @Test func `an item with an account searches by both`() {
        let query = Keychain.Item(service: "invented", account: "someone").query
        #expect(query[kSecAttrAccount as String] as? String == "someone")
    }

    @Test func `an error carries Security's status`() {
        #expect(Keychain.Error.unreadable(-1).status == -1)
        #expect(Keychain.Error.unwritable(-2).status == -2)
    }
}
