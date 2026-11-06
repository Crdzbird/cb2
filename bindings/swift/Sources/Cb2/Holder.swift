import CCb2
import Foundation

/// Holder proofs (sender constraint) for one request and one access token:
/// by the client's signing pair (the public mode) or under the kcb2.local
/// proof key the issuer put in cnf of a cb2.local token (the local mode).
public enum Holder {
    /// Proves possession of the client pair for the request at now, valid
    /// for lifetime seconds.
    public static func prove(client: SecretKey, htm: String, htu: String, nonce: String? = nil,
                             accessToken: String, jti: String, now: Int64, lifetime: Int64 = 60) throws -> String {
        let texts = [htm, htu, nonce, accessToken, jti].map { $0.map { Data($0.utf8) } }
        return try Bridge.withBuffers(texts) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            var count = 0
            try Bridge.check(cb2_holder_prove(client.handle, b[0].text, b[0].count, b[1].text, b[1].count,
                                              b[2].text, b[2].count, b[3].text, b[3].count, b[4].text, b[4].count,
                                              now, lifetime, &out, &count))
            return Bridge.text(out, count: count)
        }
    }

    /// Proves possession of the local proof key, the one in cnf of the
    /// cb2.local access token, for the request at now, valid for lifetime
    /// seconds. Available in every build.
    public static func proveLocal(proofKey: LocalKey, htm: String, htu: String, nonce: String? = nil,
                                  accessToken: String, jti: String, now: Int64, lifetime: Int64 = 60) throws -> String {
        let texts = [htm, htu, nonce, accessToken, jti].map { $0.map { Data($0.utf8) } }
        return try Bridge.withBuffers(texts) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            var count = 0
            try Bridge.check(cb2_holder_prove_local(proofKey.handle, b[0].text, b[0].count, b[1].text, b[1].count,
                                                    b[2].text, b[2].count, b[3].text, b[3].count, b[4].text,
                                                    b[4].count, now, lifetime, &out, &count))
            return Bridge.text(out, count: count)
        }
    }

    /// The htu form of a request URI: lowercase scheme and host, default
    /// port dropped, query and fragment removed.
    public static func normalizeTarget(_ uri: String) throws -> String {
        try Bridge.withText(uri) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            try Bridge.check(cb2_holder_normalize_target(b.text, b.count, &out))
            return try Bridge.required(Bridge.text(out))
        }
    }
}
