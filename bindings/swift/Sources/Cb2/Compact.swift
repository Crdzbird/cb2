import CCb2
import Foundation

/// Compact claims tokens, the experimental `cb3.local.` and `cb3.public.`
/// formats of docs/PROTOCOL.md section 15.
///
/// They take the same claims and ``Rules`` as ``Token`` and give the same
/// verdicts, with the same cryptography, but carry the claims as strict
/// CBOR and bind a ``keyDigestBytes``-byte digest of the key id instead of
/// its text, so a typical local token is a bit over half the size. The
/// issuer refuses as ``Cb2Error/argument`` what the compact profile cannot
/// carry: a custom number that is not an integer in Int64 written in
/// canonical form (`1.5`, `1e3`, `-0`), a time outside years 0000 to 9999,
/// and a `cnf` that is not a `kcb2.local` or `kcb2.public` key. A cb2 token
/// never opens here and a compact token never opens through ``Token``.
/// Holder proofs bind a compact access token as they bind a cb2 one. A
/// ``ClaimTable`` shared by the issuer and its verifiers shortens the
/// token further.
public enum Compact {
    /// The length in bytes of a key digest.
    public static let keyDigestBytes = Int(CB2_KEY_DIGEST_BYTES)

    /// Seals claims under a local key into a `cb3.local.` token, under the
    /// claim table when one is given.
    public static func seal(
        _ claims: Claims,
        key: LocalKey,
        table: ClaimTable? = nil,
        implicit: Data? = nil
    ) throws(Cb2Error) -> String {
        try with(table) { t throws(Cb2Error) in
            try ClaimsCall.issue(
                { cb2_compact_seal_with_table($0, t, $1, $2, $3, $4, $5, $6) }, claims, handle: key.handle,
                implicit: implicit)
        }
    }

    /// Signs claims with a signing pair into a `cb3.public.` token, under
    /// the claim table when one is given; a `kcb2.local` cnf is
    /// ``Cb2Error/argument``, as with ``Token/sign(_:key:implicit:)``.
    /// Available only when ``Library/hasPublic`` is true.
    public static func sign(
        _ claims: Claims,
        key: SecretKey,
        table: ClaimTable? = nil,
        implicit: Data? = nil
    ) throws(Cb2Error) -> String {
        try with(table) { t throws(Cb2Error) in
            try ClaimsCall.issue(
                { cb2_compact_sign_with_table($0, t, $1, $2, $3, $4, $5, $6) }, claims, handle: key.handle,
                implicit: implicit)
        }
    }

    /// Opens a cb3.local token under the rules and returns its claims. A
    /// token made under a claim table opens only under the same table, and
    /// one made without a table only without one; otherwise it is
    /// ``Cb2Error/invalid``.
    public static func open(
        _ token: String,
        key: LocalKey,
        table: ClaimTable? = nil,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        try with(table) { t throws(Cb2Error) in
            try ClaimsCall.check(
                { cb2_compact_open_with_table($0, t, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) }, token,
                handle: key.handle, rules: rules, implicit: implicit)
        }
    }

    /// Verifies a cb3.public token under the rules and returns its claims,
    /// with the claim table it was signed under, if any, as for
    /// ``open(_:key:table:rules:implicit:)``. Available only when
    /// ``Library/hasPublic`` is true.
    public static func verify(
        _ token: String,
        key: PublicKey,
        table: ClaimTable? = nil,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        try with(table) { t throws(Cb2Error) in
            try ClaimsCall.check(
                { cb2_compact_verify_with_table($0, t, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) }, token,
                handle: key.handle, rules: rules, implicit: implicit)
        }
    }

    /// The key digest a compact token's footer carries, unverified; nil
    /// when it has none. Compare it with ``keyDigest(_:)`` of each key id
    /// to pick the key, never to trust the token.
    public static func peekKeyDigest(_ token: String) throws(Cb2Error) -> Data? {
        try Bridge.withText(token) { b in
            var out: UnsafeMutablePointer<UInt8>? = nil
            let code = cb2_compact_peek_key_digest(b.text, b.count, &out)
            return Bridge.result(code, out.map { Bridge.bytes($0, count: keyDigestBytes) })
        }.get()
    }

    /// The digest a compact token binds for a key id, such as the
    /// ``LocalKey/keyId`` of a key. An empty id is valid; one with a control
    /// character is ``Cb2Error/argument``.
    public static func keyDigest(_ keyId: String) throws(Cb2Error) -> Data {
        let digest = try Bridge.withText(keyId) { b in
            var out: UnsafeMutablePointer<UInt8>? = nil
            let code = cb2_compact_key_digest(b.text, b.count, &out)
            return Bridge.result(code, out.map { Bridge.bytes($0, count: keyDigestBytes) })
        }.get()
        return try Bridge.required(digest)
    }

    private static func with<T>(
        _ table: ClaimTable?,
        _ body: (OpaquePointer?) throws(Cb2Error) -> T
    ) throws(Cb2Error) -> T {
        guard let table else {
            return try body(nil)
        }
        return try table.handle.use { pointer in Result { () throws(Cb2Error) in try body(pointer) } }.get()
    }
}
