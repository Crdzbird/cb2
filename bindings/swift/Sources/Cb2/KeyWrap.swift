import CCb2

/// Key wrapping: a local key under another local key, as `kcb2.local-wrap`.
public enum KeyWrap {
    /// Wraps `key` under `wrapping`.
    public static func wrap(_ key: LocalKey, with wrapping: LocalKey) throws(Cb2Error) -> String {
        let text = try wrapping.handle.use { outer in
            key.handle.use { inner in
                var out: UnsafeMutablePointer<CChar>? = nil
                let code = cb2_wrap(outer, inner, &out)
                return Bridge.result(code, Bridge.text(out))
            }
        }.get()
        return try Bridge.required(text)
    }

    /// Unwraps a `kcb2.local-wrap` text with the key it was wrapped under;
    /// any other key is ``Cb2Error/invalid``.
    public static func unwrap(_ text: String, with wrapping: LocalKey) throws(Cb2Error) -> LocalKey {
        LocalKey(
            try Bridge.handle { out in
                wrapping.handle.use { outer in
                    Bridge.withText(text) { cb2_unwrap($0.text, $0.count, outer, out) }
                }
            })
    }
}
