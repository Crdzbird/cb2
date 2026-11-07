import CCb2
import Foundation

/// A recipient pair for `kcb2.seal`, serialized as `kcb2.recipient-secret`.
///
/// Available only when ``Library/hasSeal`` is true. A key is immutable and
/// `Sendable`.
public final class RecipientKey: Sendable {
    let handle: KeyHandle

    init(_ pointer: OpaquePointer) {
        handle = KeyHandle(pointer, release: { cb2_recipient_key_free($0) })
    }

    /// A fresh random pair.
    public static func generate() throws(Cb2Error) -> RecipientKey {
        RecipientKey(try Bridge.handle { cb2_recipient_key_generate($0) })
    }

    /// The pair from its raw bytes.
    public convenience init(bytes: Data) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(bytes) { cb2_recipient_key_from_bytes($0.base, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The pair from its `kcb2.recipient-secret` text.
    public convenience init(paserk: String) throws(Cb2Error) {
        let pointer = try Bridge.handle { out in
            Bridge.withText(paserk) { cb2_recipient_key_from_paserk($0.text, $0.count, out) }
        }
        self.init(pointer)
    }

    /// The pair as `kcb2.recipient-secret` text. The C copy is wiped; the
    /// Swift string returned is ordinary memory and is not.
    public func toPaserk() throws(Cb2Error) -> String {
        try Bridge.required(handle.use { Bridge.secret(cb2_recipient_key_to_paserk($0)) })
    }

    /// The public half of the pair, the one local keys are sealed to.
    public func publicKey() throws(Cb2Error) -> RecipientPublicKey {
        RecipientPublicKey(try Bridge.handle { out in handle.use { cb2_recipient_key_public_key($0, out) } })
    }

    /// The `kcb2.rid` identifier of the pair.
    public var paserkId: String {
        get throws(Cb2Error) {
            try Bridge.required(handle.use { Bridge.text(cb2_recipient_key_paserk_id($0)) })
        }
    }
}
