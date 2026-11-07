import CCb2
import Foundation

/// Claims tokens: a JSON object of claims under a cb2.local key or signed
/// by a cb2.public pair, with the key id bound into the footer.
public enum Token {
    /// Seals claims under a local key into a `cb2.local.` token.
    public static func seal(_ claims: Claims, key: LocalKey, implicit: Data? = nil) throws(Cb2Error) -> String {
        let json = try Bridge.encode(claims)
        return try Bridge.withBuffers([json, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_token_seal(pointer, b[0].text, b[0].count, b[1].base, b[1].count, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// Signs claims with a signing pair into a `cb2.public.` token.
    public static func sign(_ claims: Claims, key: SecretKey, implicit: Data? = nil) throws(Cb2Error) -> String {
        let json = try Bridge.encode(claims)
        return try Bridge.withBuffers([json, implicit]) { b in
            key.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_token_sign(pointer, b[0].text, b[0].count, b[1].base, b[1].count, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// Opens a cb2.local claims token under the rules and returns its claims.
    public static func open(
        _ token: String,
        key: LocalKey,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        let json = try rules.json()
        let replay = ReplayBridge(rules)
        let text = try Bridge.withBuffers([Data(token.utf8), json, implicit]) { b in
            key.handle.use { pointer in
                replay.run { replayFn, proofFn, user in
                    var out: UnsafeMutablePointer<CChar>? = nil
                    var count = 0
                    let code = cb2_token_open(
                        pointer, b[0].text, b[0].count, b[1].text, b[1].count, b[2].base, b[2].count,
                        replayFn, proofFn, user, &out, &count)
                    return Bridge.result(code, Bridge.text(out, count: count))
                }
            }
        }.get()
        return try Bridge.decode(text)
    }

    /// Verifies a cb2.public claims token under the rules and returns its claims.
    public static func verify(
        _ token: String,
        key: PublicKey,
        rules: Rules = Rules(),
        implicit: Data? = nil
    ) throws(Cb2Error) -> Claims {
        let json = try rules.json()
        let replay = ReplayBridge(rules)
        let text = try Bridge.withBuffers([Data(token.utf8), json, implicit]) { b in
            key.handle.use { pointer in
                replay.run { replayFn, proofFn, user in
                    var out: UnsafeMutablePointer<CChar>? = nil
                    var count = 0
                    let code = cb2_token_verify(
                        pointer, b[0].text, b[0].count, b[1].text, b[1].count, b[2].base, b[2].count,
                        replayFn, proofFn, user, &out, &count)
                    return Bridge.result(code, Bridge.text(out, count: count))
                }
            }
        }.get()
        return try Bridge.decode(text)
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
