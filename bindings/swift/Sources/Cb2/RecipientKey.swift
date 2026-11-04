import CCb2
import Foundation

/// A recipient pair for kcb2.seal, serialized as kcb2.recipient-secret.
/// Available only when hasSeal() is true.
public final class RecipientKey {
    let handle: OpaquePointer

    init(handle: OpaquePointer) {
        self.handle = handle
    }

    deinit {
        cb2_recipient_key_free(handle)
    }

    /// A fresh random pair.
    public static func generate() throws -> RecipientKey {
        RecipientKey(handle: try Bridge.handle { cb2_recipient_key_generate($0) })
    }

    public convenience init(bytes: Data) throws {
        let handle = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_recipient_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(handle: handle)
    }

    public convenience init(paserk: String) throws {
        let handle = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_recipient_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(handle: handle)
    }

    /// The pair as kcb2.recipient-secret text; the copy handed to Swift is not wiped.
    public func toPaserk() throws -> String {
        try Bridge.required(Bridge.secret(cb2_recipient_key_to_paserk(handle)))
    }

    /// The public half of the pair, the one keys are sealed to.
    public func publicKey() throws -> RecipientPublicKey {
        RecipientPublicKey(handle: try Bridge.handle { cb2_recipient_key_public_key(handle, $0) })
    }

    /// The kcb2.rid identifier of the pair.
    public var paserkId: String {
        get throws { try Bridge.required(Bridge.text(cb2_recipient_key_paserk_id(handle))) }
    }
}
