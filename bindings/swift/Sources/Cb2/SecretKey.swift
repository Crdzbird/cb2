import CCb2
import Foundation

/// A signing pair for cb2.public tokens, serialized as `kcb2.secret`.
///
/// Available only when ``Library/hasPublic`` is true; otherwise every way
/// to make one throws ``Cb2Error/unavailable``. A key is immutable and
/// `Sendable`.
public final class SecretKey: Sendable {
    let handle: KeyHandle

    init(_ pointer: OpaquePointer) {
        handle = KeyHandle(pointer, release: { cb2_secret_key_free($0) })
    }

    init(handle: KeyHandle) {
        self.handle = handle
    }

    /// A fresh random pair.
    public static func generate() throws(Cb2Error) -> SecretKey {
        SecretKey(try Bridge.handle { cb2_secret_key_generate($0) })
    }

    /// The pair from its raw bytes.
    public convenience init(bytes: Data) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_secret_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The pair from its `kcb2.secret` text.
    public convenience init(paserk: String) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_secret_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The pair as `kcb2.secret` text. The C copy is wiped; the Swift string
    /// returned is ordinary memory and is not.
    public func toPaserk() throws(Cb2Error) -> String {
        try Bridge.required(handle.use { Bridge.secret(cb2_secret_key_to_paserk($0)) })
    }

    /// The public half of the pair, the key verifiers hold.
    public func publicKey() throws(Cb2Error) -> PublicKey {
        PublicKey(try Bridge.handle { out in handle.use { cb2_secret_key_public_key($0, out) } })
    }

    /// The `kcb2.pid` identifier of the pair, which is that of its public half.
    public var paserkId: String {
        get throws(Cb2Error) {
            try publicKey().paserkId
        }
    }

    /// The key id bound into the footer of tokens: the PASERK id unless
    /// changed with ``withKeyId(_:)`` or removed with ``withoutKeyId()``.
    public var keyId: String? {
        handle.use { Bridge.text(cb2_secret_key_key_id($0)) }
    }

    /// The same pair with another key id; an identifier the library
    /// refuses is ``Cb2Error/argument``.
    public func withKeyId(_ id: String) throws(Cb2Error) -> SecretKey {
        let copy = try handle.copy(
            export: { cb2_secret_key_to_paserk($0) },
            secret: true,
            import: { cb2_secret_key_from_paserk($0, $1, $2) },
            adjust: { pointer in Bridge.withText(id) { cb2_secret_key_set_key_id(pointer, $0.text, $0.count) } }
        )
        return SecretKey(handle: copy)
    }

    /// The same pair with no key id.
    public func withoutKeyId() throws(Cb2Error) -> SecretKey {
        let copy = try handle.copy(
            export: { cb2_secret_key_to_paserk($0) },
            secret: true,
            import: { cb2_secret_key_from_paserk($0, $1, $2) },
            adjust: { pointer in
                cb2_secret_key_clear_key_id(pointer)
                return 0
            }
        )
        return SecretKey(handle: copy)
    }
}
