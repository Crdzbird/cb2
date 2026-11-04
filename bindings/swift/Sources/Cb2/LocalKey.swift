import CCb2
import Foundation

/// A symmetric key for cb2.local tokens, serialized as kcb2.local.
public final class LocalKey {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        cb2_local_key_free(handle)
    }

    /// A fresh random key.
    public static func generate() throws -> LocalKey {
        LocalKey(handle: try Bridge.handle { cb2_local_key_generate($0) })
    }

    /// The key from its raw bytes; weak or wrongly sized material is refused.
    public convenience init(bytes: Data) throws {
        let handle = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_local_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The key from its kcb2.local text.
    public convenience init(paserk: String) throws {
        let handle = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_local_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The key as kcb2.local text; the copy handed to Swift is not wiped.
    public func toPaserk() throws -> String {
        try Bridge.required(Bridge.secret(cb2_local_key_to_paserk(handle)))
    }

    /// The kcb2.lid identifier of the key.
    public var paserkId: String {
        get throws { try Bridge.required(Bridge.text(cb2_local_key_paserk_id(handle))) }
    }

    /// The key id bound into tokens, the paserk id unless set or cleared.
    public var keyId: String? {
        Bridge.text(cb2_local_key_key_id(handle))
    }

    /// Sets the key id; an identifier the library refuses is an argument error.
    public func setKeyId(_ id: String) throws {
        try Bridge.check(Bridge.withText(id) { cb2_local_key_set_key_id(handle, $0.text, $0.count) })
    }

    public func clearKeyId() {
        cb2_local_key_clear_key_id(handle)
    }
}
