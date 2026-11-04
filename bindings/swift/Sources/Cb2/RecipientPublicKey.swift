import CCb2
import Foundation

/// The public half of a recipient pair, serialized as kcb2.recipient.
/// Available only when hasSeal() is true.
public final class RecipientPublicKey {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        cb2_recipient_public_key_free(handle)
    }

    public convenience init(bytes: Data) throws {
        let handle = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_recipient_public_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(handle: handle)
    }

    public convenience init(paserk: String) throws {
        let handle = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_recipient_public_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The key as kcb2.recipient text.
    public func toPaserk() throws -> String {
        try Bridge.required(Bridge.text(cb2_recipient_public_key_to_paserk(handle)))
    }

    /// The kcb2.rid identifier of the key.
    public var paserkId: String {
        get throws { try Bridge.required(Bridge.text(cb2_recipient_public_key_paserk_id(handle))) }
    }
}
