import CCb2
import Foundation

/// Claims tokens: a JSON object of registered claims (times as RFC 3339
/// strings) and custom claims, with the key id bound into the footer.
public enum Token {
    public static func seal(key: LocalKey, claims: [String: Any], implicit: Data? = nil) throws -> String {
        try Bridge.withBuffers([try Bridge.claimsJson(claims), implicit]) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            var count = 0
            try Bridge.check(cb2_token_seal(key.handle, b[0].text, b[0].count, b[1].base, b[1].count, &out, &count))
            return Bridge.text(out, count: count)
        }
    }

    public static func sign(key: SecretKey, claims: [String: Any], implicit: Data? = nil) throws -> String {
        try Bridge.withBuffers([try Bridge.claimsJson(claims), implicit]) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            var count = 0
            try Bridge.check(cb2_token_sign(key.handle, b[0].text, b[0].count, b[1].base, b[1].count, &out, &count))
            return Bridge.text(out, count: count)
        }
    }

    /// Opens a cb2.local claims token under the rules and returns its claims.
    public static func open(token: String, key: LocalKey, rules: Rules = Rules(), implicit: Data? = nil) throws -> [String: Any] {
        let bridge = ReplayBridge(replay: rules.replay, proofReplay: rules.proofReplay)
        return try Bridge.withBuffers([Data(token.utf8), try rules.json(), implicit]) { b in
            try bridge.run { replay, proofReplay, user in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                try Bridge.check(cb2_token_open(key.handle, b[0].text, b[0].count, b[1].text, b[1].count,
                                                b[2].base, b[2].count, replay, proofReplay, user, &out, &count))
                return try Bridge.claims(from: Bridge.text(out, count: count))
            }
        }
    }

    /// Verifies a cb2.public claims token under the rules and returns its claims.
    public static func verify(token: String, key: PublicKey, rules: Rules = Rules(), implicit: Data? = nil) throws -> [String: Any] {
        let bridge = ReplayBridge(replay: rules.replay, proofReplay: rules.proofReplay)
        return try Bridge.withBuffers([Data(token.utf8), try rules.json(), implicit]) { b in
            try bridge.run { replay, proofReplay, user in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                try Bridge.check(cb2_token_verify(key.handle, b[0].text, b[0].count, b[1].text, b[1].count,
                                                  b[2].base, b[2].count, replay, proofReplay, user, &out, &count))
                return try Bridge.claims(from: Bridge.text(out, count: count))
            }
        }
    }

    /// The key id a token's footer names, unverified; nil when none.
    public static func peekKeyId(token: String) throws -> String? {
        try Bridge.withText(token) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            try Bridge.check(cb2_peek_key_id(b.text, b.count, &out))
            return Bridge.text(out)
        }
    }
}
