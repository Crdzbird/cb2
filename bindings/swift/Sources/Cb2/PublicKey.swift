import CCb2
import Foundation

/// The verifying half of a signing pair, serialized as kcb2.public.
/// Available only when hasPublic() is true.
public final class PublicKey {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        cb2_public_key_free(handle)
    }

    public convenience init(bytes: Data) throws {
        let handle = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_public_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(handle: handle)
    }

    public convenience init(paserk: String) throws {
        let handle = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_public_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The key as kcb2.public text.
    public func toPaserk() throws -> String {
        try Bridge.required(Bridge.text(cb2_public_key_to_paserk(handle)))
    }

    /// The kcb2.pid identifier of the key.
    public var paserkId: String {
        get throws { try Bridge.required(Bridge.text(cb2_public_key_paserk_id(handle))) }
    }

    /// The key id expected in token footers, the paserk id unless set or cleared.
    public var keyId: String? {
        Bridge.text(cb2_public_key_key_id(handle))
    }

    /// Sets the key id; an identifier the library refuses is an argument error.
    public func setKeyId(_ id: String) throws {
        try Bridge.check(Bridge.withText(id) { cb2_public_key_set_key_id(handle, $0.text, $0.count) })
    }

    public func clearKeyId() {
        cb2_public_key_clear_key_id(handle)
    }
}
