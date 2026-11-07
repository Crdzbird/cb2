import CCb2
import Foundation

/// The public half of a recipient pair, serialized as `kcb2.recipient`.
///
/// Available only when ``Library/hasSeal`` is true. A key is immutable and
/// `Sendable`.
public final class RecipientPublicKey: Sendable {
    let handle: KeyHandle

    init(_ pointer: OpaquePointer) {
        handle = KeyHandle(pointer, release: { cb2_recipient_public_key_free($0) })
    }

    /// The key from its raw bytes.
    public convenience init(bytes: Data) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_recipient_public_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key from its `kcb2.recipient` text.
    public convenience init(paserk: String) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_recipient_public_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The key as `kcb2.recipient` text.
    public func toPaserk() throws(Cb2Error) -> String {
        try Bridge.required(handle.use { Bridge.text(cb2_recipient_public_key_to_paserk($0)) })
    }

    /// The `kcb2.rid` identifier of the key.
    public var paserkId: String {
        get throws(Cb2Error) {
            try Bridge.required(handle.use { Bridge.text(cb2_recipient_public_key_paserk_id($0)) })
        }
    }
}
