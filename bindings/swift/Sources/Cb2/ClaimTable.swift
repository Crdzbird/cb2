import CCb2
import Foundation

/// A claim table for compact tokens, docs/PROTOCOL.md section 15.5: an
/// ordered list of 1 to 256 distinct, non-empty strings, typically the
/// issuer's name and its audiences, that an issuer and its verifiers
/// configure alike. Under a table an `iss` or `aud` equal to an entry
/// travels as its index, and the table's digest is bound into the token,
/// so it opens only under the same table, in the same order.
///
/// A table is immutable and `Sendable`: share one instance between tasks
/// freely.
public final class ClaimTable: Sendable {
    /// The length in bytes of a table digest.
    public static let digestBytes = Int(CB2_CLAIM_TABLE_DIGEST_BYTES)

    let handle: KeyHandle

    /// The table of the entries, in order. An empty list, a repeated or
    /// empty entry, or one the library refuses as an identifier, such as
    /// one with a control character, is ``Cb2Error/argument``.
    public init(_ entries: [String]) throws(Cb2Error) {
        var json: [UInt8] = []
        try JSONText.write(.array(entries.map { .string($0) }), into: &json)
        let pointer = try Bridge.handle { out in
            Bridge.withBytes(Data(json)) { cb2_claim_table_from_json($0.text, $0.count, out) }
        }
        handle = KeyHandle(pointer, release: { cb2_claim_table_free($0) })
    }

    /// The table's digest, the same for every party holding the same
    /// entries in the same order, so two parties can compare their tables.
    public var digest: Data {
        get throws(Cb2Error) {
            let digest = handle.use { pointer in
                var out: UnsafeMutablePointer<UInt8>? = nil
                let code = cb2_claim_table_digest(pointer, &out)
                return Bridge.result(code, out.map { Bridge.bytes($0, count: Self.digestBytes) })
            }
            return try Bridge.required(digest.get())
        }
    }
}
