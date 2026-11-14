import CCb2
import Foundation

/// Claims tokens: a JSON object of claims under a cb2.local key or signed
/// by a cb2.public pair, with the key id bound into the footer.
public enum Token {
    /// Seals claims under a local key into a `cb2.local.` token.
    public static func seal(_ claims: Claims, key: LocalKey, implicit: Data? = nil) throws(Cb2Error) -> String {
        try ClaimsCall.issue(cb2_token_seal, claims, handle: key.handle, implicit: implicit)
    }

    /// Signs claims with a signing pair into a `cb2.public.` token.
    public static func sign(_ claims: Claims, key: SecretKey, implicit: Data? = nil) throws(Cb2Error) -> String {
        try ClaimsCall.issue(cb2_token_sign, claims, handle: key.handle, implicit: implicit)
    }

    /// Opens a cb2.local claims token under the rules and returns its claims.
    public static func open(
        _ token: String,
        key: LocalKey,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        try ClaimsCall.check(cb2_token_open, token, handle: key.handle, rules: rules, implicit: implicit)
    }

    /// Verifies a cb2.public claims token under the rules and returns its claims.
    public static func verify(
        _ token: String,
        key: PublicKey,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        try ClaimsCall.check(cb2_token_verify, token, handle: key.handle, rules: rules, implicit: implicit)
    }

    /// The key id a token's footer names, unverified; nil when it has none.
    /// Use it to pick the key, never to trust the token.
    public static func peekKeyId(_ token: String) throws(Cb2Error) -> String? {
        try Bridge.withText(token) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            let code = cb2_peek_key_id(b.text, b.count, &out)
            return Bridge.result(code, Bridge.text(out))
        }.get()
    }
}
