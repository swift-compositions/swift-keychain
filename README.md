# swift-keychain

One owner for a generic password in the login keychain: `Keychain.Item(service:account:)`, with `read`, `write` and `remove`. Apple's Security framework stays behind this package. `Keychain.Item.Tool` reads through `/usr/bin/security` instead, for an item that tool created and so already trusts: no process reading it this way is asked for access, however often it is rebuilt.
