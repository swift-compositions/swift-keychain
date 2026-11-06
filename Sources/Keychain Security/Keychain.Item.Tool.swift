#if os(macOS)
    import Foundation

    extension Keychain.Item {
        /// An item read through `/usr/bin/security`, for one that tool created by hand and so already trusts: no process
        /// reading it this way is asked for access, however often it's rebuilt. Values come back through a pipe and are
        /// never logged, printed or stored here.
        public struct Tool: Hashable, Sendable {
            public let item: Keychain.Item
        }

        public var tool: Tool { Tool(item: self) }
    }

    extension Keychain.Item.Tool {
        private var arguments: [String] {
            ["find-generic-password", "-s", item.service] + (item.account.map { ["-a", $0] } ?? [])
        }

        /// The kept value; nil when none is kept. A value that isn't one line of printable text comes back as hex,
        /// as `security` prints it.
        public func read() throws(Keychain.Error) -> String? {
            try run(arguments + ["-w"]).map { $0.trimmingCharacters(in: .newlines) }.flatMap { $0.isEmpty ? nil : $0 }
        }

        /// The item's Account attribute.
        public func account() throws(Keychain.Error) -> String? {
            guard let attributes = try run(arguments) else { return nil }
            for line in attributes.split(separator: "\n") where line.contains("\"acct\"<blob>=") {
                let value = line.split(separator: "=", maxSplits: 1).last.map(String.init) ?? ""
                if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 { return String(value.dropFirst().dropLast()) }
                // `security` prints non-ASCII values as hex, followed by an escaped rendering.
                if value.hasPrefix("0x"), let hex = value.dropFirst(2).split(separator: " ").first {
                    var bytes: [UInt8] = []
                    var index = hex.startIndex
                    while index < hex.endIndex, let next = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex), let byte = UInt8(hex[index..<next], radix: 16) {
                        bytes.append(byte)
                        index = next
                    }
                    return String(decoding: bytes, as: UTF8.self)
                }
            }
            return nil
        }

        private func run(_ arguments: [String]) throws(Keychain.Error) -> String? {
            let process = Process(), output = Pipe()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
            process.arguments = arguments
            process.standardOutput = output
            process.standardError = FileHandle.nullDevice
            do {
                try process.run()
            } catch {
                throw .unreadable(-1)
            }
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            // 44 is security's "the specified item could not be found in the keychain".
            if process.terminationStatus == 44 { return nil }
            guard process.terminationStatus == 0 else { throw .unreadable(process.terminationStatus) }
            return String(decoding: data, as: UTF8.self)
        }
    }
#endif
