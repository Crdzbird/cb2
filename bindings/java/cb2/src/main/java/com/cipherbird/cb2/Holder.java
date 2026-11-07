package com.cipherbird.cb2;

/**
 * Holder proofs (sender constraint) for one request and one access token.
 * The client makes the proof; the server checks it through
 * {@link Rules#proof(String)} and {@link Rules#request(String, String)},
 * with a proof replay check. There are two modes: a proof by the client's
 * signing pair, whose public half the issuer put in cnf (the public
 * mode), and a proof under the kcb2.local proof key the issuer put in cnf
 * of a cb2.local token and handed to the client (the local mode).
 */
public final class Holder {
    private Holder() {
    }

    /**
     * Proves possession of the client pair for one request (public mode).
     *
     * @param client the client's signing pair
     * @param htm the request method, such as {@code "GET"}
     * @param htu the request target, an absolute http or https URI
     * @param nonce the server nonce, or null for none
     * @param accessToken the access token the proof goes with
     * @param jti a unique id for this proof
     * @param now the proof's issue time in Unix seconds
     * @param lifetime the proof's validity in seconds
     * @return the cb2.holder-public proof
     * @throws Cb2Exception with {@link Code#ARGUMENT} for a target that is
     *     not an absolute http or https URI, or {@link Code#UNAVAILABLE}
     *     when the build has no cb2.public
     */
    public static String prove(SecretKey client, String htm, String htu, String nonce, String accessToken,
            String jti, long now, long lifetime) {
        byte[] m = Text.utf8(Text.required(htm, "htm"));
        byte[] u = Text.utf8(Text.required(htu, "htu"));
        byte[] n = Text.utf8(nonce);
        byte[] a = Text.utf8(Text.required(accessToken, "accessToken"));
        byte[] j = Text.utf8(Text.required(jti, "jti"));
        return Text.string(Text.required(client, "client").handle.use(
                h -> Native.holderProve(h, m, u, n, a, j, now, lifetime)));
    }

    /**
     * Proves possession of the local proof key for one request (local
     * mode): the key the issuer wrote into cnf of the cb2.local access
     * token and handed to the client with it. Available in every build.
     *
     * @param proofKey the proof key from cnf
     * @param htm the request method, such as {@code "GET"}
     * @param htu the request target, an absolute http or https URI
     * @param nonce the server nonce, or null for none
     * @param accessToken the access token the proof goes with
     * @param jti a unique id for this proof
     * @param now the proof's issue time in Unix seconds
     * @param lifetime the proof's validity in seconds
     * @return the cb2.holder-local proof
     * @throws Cb2Exception with {@link Code#ARGUMENT} for a target that is
     *     not an absolute http or https URI
     */
    public static String proveLocal(LocalKey proofKey, String htm, String htu, String nonce, String accessToken,
            String jti, long now, long lifetime) {
        byte[] m = Text.utf8(Text.required(htm, "htm"));
        byte[] u = Text.utf8(Text.required(htu, "htu"));
        byte[] n = Text.utf8(nonce);
        byte[] a = Text.utf8(Text.required(accessToken, "accessToken"));
        byte[] j = Text.utf8(Text.required(jti, "jti"));
        return Text.string(Text.required(proofKey, "proofKey").handle.use(
                h -> Native.holderProveLocal(h, m, u, n, a, j, now, lifetime)));
    }

    /**
     * The normalised form of a request target, as a proof binds it:
     * lowercase scheme and host, the default port dropped, query and
     * fragment removed.
     *
     * @param uri an absolute http or https URI
     * @return the normalised target
     * @throws Cb2Exception with {@link Code#ARGUMENT} for anything else
     */
    public static String normalizeTarget(String uri) {
        return Text.string(Native.holderNormalizeTarget(Text.utf8(Text.required(uri, "uri"))));
    }
}
