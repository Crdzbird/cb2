import CCb2
import Foundation

/// A symmetric key for cb2.local tokens, serialized as `kcb2.local`.
///
/// A key is immutable and `Sendable`: share one instance between tasks
/// freely. ``withKeyId(_:)`` and ``withoutKeyId()`` return a new key.
public final class LocalKey: Sendable {
    let handle: KeyHandle

    init(_ pointer: OpaquePointer) {
        handle = KeyHandle(pointer, release: { cb2_local_key_free($0) })
    }

    init(handle: KeyHandle) {
        self.handle = handle
    }

    /// A fresh random key.
    public static func generate() throws(Cb2Error) -> LocalKey {
        LocalKey(try Bridge.handle { cb2_local_key_generate($0) })
    }

    /// The key from its 32 raw bytes; weak or wrongly sized material is
    /// refused as ``Cb2Error/argument``.
    public convenience init(bytes: Data) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_local_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key from its `kcb2.local` text.
    public convenience init(paserk: String) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_local_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key as `kcb2.local` text. The C copy is wiped; the Swift string
    /// returned is ordinary memory and is not.
    public func toPaserk() throws(Cb2Error) -> String {
        try Bridge.required(handle.use { Bridge.secret(cb2_local_key_to_paserk($0)) })
    }

    /// The `kcb2.lid` identifier of the key.
    public var paserkId: String {
        get throws(Cb2Error) {
            try Bridge.required(handle.use { Bridge.text(cb2_local_key_paserk_id($0)) })
        }
    }

    /// The key id bound into the footer of tokens: the PASERK id unless
    /// changed with ``withKeyId(_:)`` or removed with ``withoutKeyId()``.
    public var keyId: String? {
        handle.use { Bridge.text(cb2_local_key_key_id($0)) }
    }

    /// The same key with another key id; an identifier the library refuses,
    /// such as one with a zero-width space, is ``Cb2Error/argument``.
    public func withKeyId(_ id: String) throws(Cb2Error) -> LocalKey {
        let copy = try handle.copy(
            export: { cb2_local_key_to_paserk($0) },
            secret: true,
            import: { cb2_local_key_from_paserk($0, $1, $2) },
            adjust: { pointer in Bridge.withText(id) { cb2_local_key_set_key_id(pointer, $0.text, $0.count) } }
        )
        return LocalKey(handle: copy)
    }

    /// The same key with no key id, so tokens carry none in their footer.
    public func withoutKeyId() throws(Cb2Error) -> LocalKey {
        let copy = try handle.copy(
            export: { cb2_local_key_to_paserk($0) },
            secret: true,
            import: { cb2_local_key_from_paserk($0, $1, $2) },
            adjust: { pointer in
                cb2_local_key_clear_key_id(pointer)
                return 0
            }
        )
        return LocalKey(handle: copy)
    }
}
