import CCb2
import Foundation

/// Raw cb2.local tokens: any bytes as the message, an optional footer and
/// implicit assertion that the opener must present again.
public enum Local {
    public static func seal(key: LocalKey, message: Data, footer: Data? = nil, implicit: Data? = nil) throws -> String {
        try Bridge.withBuffers([message, footer, implicit]) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            var count = 0
            try Bridge.check(cb2_local_seal(key.handle, b[0].base, b[0].count, b[1].base, b[1].count,
                                            b[2].base, b[2].count, &out, &count))
            return Bridge.text(out, count: count)
        }
    }

    /// Opens a token; maxTokenBytes 0 means the library's default limit.
    public static func open(token: String, key: LocalKey, footer: Data? = nil, implicit: Data? = nil,
                            maxTokenBytes: Int = 0) throws -> Data {
        try Bridge.withBuffers([Data(token.utf8), footer, implicit]) { b in
            var out: UnsafeMutablePointer<UInt8>? = nil
            var count = 0
            try Bridge.check(cb2_local_open(key.handle, b[0].text, b[0].count, b[1].base, b[1].count,
                                            b[2].base, b[2].count, maxTokenBytes, &out, &count))
            return Bridge.bytes(out, count: count)
        }
    }
}
