import CCb2
import Foundation

/// A signing pair for cb2.public tokens, serialized as kcb2.secret.
/// Available only when hasPublic() is true.
public final class SecretKey {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        cb2_secret_key_free(handle)
    }

    /// A fresh random pair.
    public static func generate() throws -> SecretKey {
        SecretKey(handle: try Bridge.handle { cb2_secret_key_generate($0) })
    }

    public convenience init(bytes: Data) throws {
        let handle = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_secret_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(handle: handle)
    }

    public convenience init(paserk: String) throws {
        let handle = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_secret_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The pair as kcb2.secret text; the copy handed to Swift is not wiped.
    public func toPaserk() throws -> String {
        try Bridge.required(Bridge.secret(cb2_secret_key_to_paserk(handle)))
    }

    /// The public half of the pair.
    public func publicKey() throws -> PublicKey {
        PublicKey(handle: try Bridge.handle { cb2_secret_key_public_key(handle, $0) })
    }

    /// The kcb2.pid identifier of the pair, which is that of its public half.
    public var paserkId: String {
        get throws { try publicKey().paserkId }
    }

    /// The key id bound into tokens, the paserk id unless set or cleared.
    public var keyId: String? {
        Bridge.text(cb2_secret_key_key_id(handle))
    }

    /// Sets the key id; an identifier the library refuses is an argument error.
    public func setKeyId(_ id: String) throws {
        try Bridge.check(Bridge.withText(id) { cb2_secret_key_set_key_id(handle, $0.text, $0.count) })
    }

    public func clearKeyId() {
        cb2_secret_key_clear_key_id(handle)
    }
}
