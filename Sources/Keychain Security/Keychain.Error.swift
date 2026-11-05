extension Keychain {
    /// Why the keychain did what it did not do, with Security's status.
    public enum Error: Swift.Error, Equatable, Sendable {
        /// The keychain refused to read: locked, this build may not access the item, or the value isn't UTF-8.
        case unreadable(Int32)
        /// The keychain refused to keep or remove the value.
        case unwritable(Int32)
    }
}

extension Keychain.Error {
    public var status: Int32 {
        switch self {
        case .unreadable(let status), .unwritable(let status): status
        }
    }
}
