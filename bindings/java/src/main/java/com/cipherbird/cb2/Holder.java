package com.cipherbird.cb2;

/**
 * Holder proofs (sender constraint): a proof by the client's signing pair
 * for one request and one access token, checked by the server through
 * the proof and request members of {@link Rules}.
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

    /** The normalised form of a request target, as the proof binds it. */
    public static String normalizeTarget(String uri) {
        return Text.string(Native.holderNormalizeTarget(Text.utf8(Text.required(uri, "uri"))));
    }
}
