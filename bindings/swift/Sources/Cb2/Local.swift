import CCb2
import Foundation

/// Raw cb2.local tokens: any bytes as the message, with an optional footer
/// and an implicit assertion that the opener must present again.
public enum Local {
    /// Seals the message under the key into a `cb2.local.` token.
    public static func seal(
        _ message: Data,
        key: LocalKey,
        footer: Data? = nil,
        implicit: Data? = nil
    ) throws(Cb2Error) -> String {
        try Bridge.withBuffers([message, footer, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_local_seal(
                    pointer, b[0].base, b[0].count, b[1].base, b[1].count, b[2].base, b[2].count, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// Opens a token and returns its message; `maxTokenBytes` 0 keeps the
    /// library's default limit.
    public static func open(
        _ token: String,
        key: LocalKey,
        footer: Data? = nil,
        implicit: Data? = nil,
        maxTokenBytes: Int = 0
    ) throws(Cb2Error) -> Data {
        try Bridge.withBuffers([Data(token.utf8), footer, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<UInt8>? = nil
                var count = 0
                let code = cb2_local_open(
                    pointer, b[0].text, b[0].count, b[1].base, b[1].count, b[2].base, b[2].count, maxTokenBytes,
                    &out, &count)
                return Bridge.result(code, Bridge.bytes(out, count: count))
            }
        }.get()
    }
}
