import CCb2

/// Key wrapping: a local key under another local key, as kcb2.local-wrap.
public enum KeyWrap {
    public static func wrap(_ key: LocalKey, with wrapping: LocalKey) throws -> String {
        var out: UnsafeMutablePointer<CChar>? = nil
        try Bridge.check(cb2_wrap(wrapping.handle, key.handle, &out))
        return try Bridge.required(Bridge.text(out))
    }

    public static func unwrap(_ text: String, with wrapping: LocalKey) throws -> LocalKey {
        let handle = try Bridge.handle { out in
            Bridge.withText(text) { cb2_unwrap($0.text, $0.count, wrapping.handle, out) }
        }
        return LocalKey(handle: handle)
    }
}
