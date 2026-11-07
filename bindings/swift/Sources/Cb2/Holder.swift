import CCb2
import Foundation

/// Holder proofs (sender constraint) for one request and one access token.
///
/// The public mode proves possession of the client's signing pair, whose
/// public half the issuer put in `cnf`. The local mode proves possession of
/// the `kcb2.local` proof key the issuer put in `cnf` of a cb2.local token
/// and handed to the client with it. A verifier checks either kind by
/// setting ``Rules/proof`` and ``Rules/request``.
public enum Holder {
    /// Proves possession of the client pair for the request, valid for
    /// `lifetime` seconds from `now`. Available only when
    /// ``Library/hasPublic`` is true.
    public static func prove(
        client: SecretKey,
        request: HolderRequest,
        accessToken: String,
        jti: String,
        now: Int64 = Int64(Date().timeIntervalSince1970),
        lifetime: Int64 = 60
    ) throws(Cb2Error) -> String {
        let texts = Bridge.texts([request.htm, request.htu, request.nonce, accessToken, jti])
        return try Bridge.withBuffers(texts) { b in
            client.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_holder_prove(
                    pointer, b[0].text, b[0].count, b[1].text, b[1].count, b[2].text, b[2].count, b[3].text,
                    b[3].count, b[4].text, b[4].count, now, lifetime, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// Proves possession of the local proof key, the one in `cnf` of the
    /// cb2.local access token, for the request, valid for `lifetime`
    /// seconds from `now`. Available in every build.
    public static func proveLocal(
        proofKey: LocalKey,
        request: HolderRequest,
        accessToken: String,
        jti: String,
        now: Int64 = Int64(Date().timeIntervalSince1970),
        lifetime: Int64 = 60
    ) throws(Cb2Error) -> String {
        let texts = Bridge.texts([request.htm, request.htu, request.nonce, accessToken, jti])
        return try Bridge.withBuffers(texts) { b in
            proofKey.handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = cb2_holder_prove_local(
                    pointer, b[0].text, b[0].count, b[1].text, b[1].count, b[2].text, b[2].count, b[3].text,
                    b[3].count, b[4].text, b[4].count, now, lifetime, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    /// The `htu` form of a request URI: lowercase scheme and host, default
    /// port dropped, query and fragment removed.
    public static func normalizeTarget(_ uri: String) throws(Cb2Error) -> String {
        let text = try Bridge.withText(uri) { b in
            var out: UnsafeMutablePointer<CChar>? = nil
            let code = cb2_holder_normalize_target(b.text, b.count, &out)
            return Bridge.result(code, Bridge.text(out))
        }.get()
        return try Bridge.required(text)
    }
}
