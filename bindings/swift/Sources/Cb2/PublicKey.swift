import CCb2
import Foundation

/// The verifying half of a signing pair, serialized as `kcb2.public`.
///
/// Available only when ``Library/hasPublic`` is true. A key is immutable
/// and `Sendable`.
public final class PublicKey: Sendable {
    let handle: KeyHandle

    init(_ pointer: OpaquePointer) {
        handle = KeyHandle(pointer, release: { cb2_public_key_free($0) })
    }

    init(handle: KeyHandle) {
        self.handle = handle
    }

    /// The key from its raw bytes.
    public convenience init(bytes: Data) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_public_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key from its `kcb2.public` text.
    public convenience init(paserk: String) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_public_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key as `kcb2.public` text.
    public func toPaserk() throws(Cb2Error) -> String {
        try Bridge.required(handle.use { Bridge.text(cb2_public_key_to_paserk($0)) })
    }

    /// The `kcb2.pid` identifier of the key.
    public var paserkId: String {
        get throws(Cb2Error) {
            try Bridge.required(handle.use { Bridge.text(cb2_public_key_paserk_id($0)) })
        }
    }

    /// The key id expected in token footers: the PASERK id unless changed
    /// with ``withKeyId(_:)`` or removed with ``withoutKeyId()``.
    public var keyId: String? {
        handle.use { Bridge.text(cb2_public_key_key_id($0)) }
    }

    /// The same key with another key id; an identifier the library refuses
    /// is ``Cb2Error/argument``.
    public func withKeyId(_ id: String) throws(Cb2Error) -> PublicKey {
        let copy = try handle.copy(
            export: { cb2_public_key_to_paserk($0) },
            secret: false,
            import: { cb2_public_key_from_paserk($0, $1, $2) },
            adjust: { pointer in Bridge.withText(id) { cb2_public_key_set_key_id(pointer, $0.text, $0.count) } }
        )
        return PublicKey(handle: copy)
    }

    /// The same key with no key id.
    public func withoutKeyId() throws(Cb2Error) -> PublicKey {
        let copy = try handle.copy(
            export: { cb2_public_key_to_paserk($0) },
            secret: false,
            import: { cb2_public_key_from_paserk($0, $1, $2) },
            adjust: { pointer in
                cb2_public_key_clear_key_id(pointer)
                return 0
            }
        )
        return PublicKey(handle: copy)
    }
}
