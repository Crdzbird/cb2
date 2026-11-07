import CCb2
import Foundation

/// Raw cb2.public tokens: any bytes as the message, signed by a pair and
/// verified by its public half. Available only when ``Library/hasPublic``
/// is true.
public enum Public {
    /// Signs the message into a `cb2.public.` token.
    public static func sign(
        _ message: Data,
        key: SecretKey,
        footer: Data? = nil,
        implicit: Data? = nil
    ) throws(Cb2Error) -> String {
        try Bridge.withBuffers([message, footer, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_public_sign(
                    pointer, b[0].base, b[0].count, b[1].base, b[1].count, b[2].base, b[2].count, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// Verifies a token and returns its message; `maxTokenBytes` 0 keeps
    /// the library's default limit.
    public static func verify(
        _ token: String,
        key: PublicKey,
        footer: Data? = nil,
        implicit: Data? = nil,
        maxTokenBytes: Int = 0
    ) throws(Cb2Error) -> Data {
        try Bridge.withBuffers([Data(token.utf8), footer, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<UInt8>? = nil
                var count = 0
                let code = cb2_public_verify(
                    pointer, b[0].text, b[0].count, b[1].base, b[1].count, b[2].base, b[2].count, maxTokenBytes,
                    &out, &count)
                return Bridge.result(code, Bridge.bytes(out, count: count))
            }
        }.get()
    }
}
