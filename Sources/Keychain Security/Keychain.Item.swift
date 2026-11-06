#if canImport(Security)
import Foundation
import Security

extension Keychain {
    /// A generic password, found by its service and, when it has one, its account.
    public struct Item: Hashable, Sendable {
        public let service: String
        /// nil finds an item of this service under any account, and adds one under the user's name.
        public let account: String?

        public init(service: String, account: String? = nil) {
            self.service = service
            self.account = account
        }
    }
}

extension Keychain.Item {
    package var query: [String: Any] {
        var query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if let account { query[kSecAttrAccount as String] = account }
        return query
    }

    /// The kept value; nil when none is kept.
    public func read() throws(Keychain.Error) -> String? {
        var search = query
        search[kSecReturnData as String] = true
        search[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = unsafe SecItemCopyMatching(search as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else { throw .unreadable(status) }
        guard let value = String(data: data, encoding: .utf8) else { throw .unreadable(errSecDecode) }
        return value
    }

    /// Updates the item in place, adding it when it is not there, so a failed write never loses the kept value.
    public func write(_ value: String) throws(Keychain.Error) {
        let data = Data(value.utf8)
        var status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var added = query
            added[kSecAttrAccount as String] = account ?? NSUserName()
            added[kSecValueData as String] = data
            status = SecItemAdd(added as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw .unwritable(status) }
    }

    /// Forgets the kept value; nothing kept is not a failure.
    public func remove() throws(Keychain.Error) {
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw .unwritable(status) }
    }
}
#endif
