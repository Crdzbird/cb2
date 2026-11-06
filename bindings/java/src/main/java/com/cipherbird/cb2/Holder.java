package com.cipherbird.cb2;

/**
 * Holder proofs (sender constraint) for one request and one access token,
 * checked by the server through the proof and request members of
 * {@link Rules}: a proof by the client's signing pair (the public mode) or
 * under the kcb2.local proof key the issuer put in cnf of a cb2.local
 * token (the local mode).
 */
public final class Holder {
    private Holder() {
    }

    /**
     * Proves possession of client for one request. nonce may be null;
     * now is Unix seconds and lifetime the proof's validity in seconds.
     */
    public static String prove(SecretKey client, String htm, String htu, String nonce, String accessToken,
            String jti, long now, long lifetime) {
        return Text.string(Native.holderProve(client.handle(), Text.utf8(Text.required(htm, "htm")),
                Text.utf8(Text.required(htu, "htu")), Text.utf8(nonce),
                Text.utf8(Text.required(accessToken, "accessToken")), Text.utf8(Text.required(jti, "jti")), now,
                lifetime));
    }

    /**
     * Proves possession of the local proof key for one request, the key
     * the issuer wrote into cnf of the cb2.local accessToken and handed to
     * the client with it. Available in every build. nonce may be null.
     */
    public static String proveLocal(LocalKey proofKey, String htm, String htu, String nonce, String accessToken,
            String jti, long now, long lifetime) {
        return Text.string(Native.holderProveLocal(proofKey.handle(), Text.utf8(Text.required(htm, "htm")),
                Text.utf8(Text.required(htu, "htu")), Text.utf8(nonce),
                Text.utf8(Text.required(accessToken, "accessToken")), Text.utf8(Text.required(jti, "jti")), now,
                lifetime));
    }

    /** The normalised form of a request target, as the proof binds it. */
    public static String normalizeTarget(String uri) {
        return Text.string(Native.holderNormalizeTarget(Text.utf8(Text.required(uri, "uri"))));
    }
}
