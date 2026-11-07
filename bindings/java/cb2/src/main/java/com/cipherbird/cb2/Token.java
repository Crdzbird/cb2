package com.cipherbird.cb2;

/**
 * Claims tokens. Claims are JSON text: an object with the registered
 * claims (iss, sub, aud, exp, nbf, iat, jti, cnf; times as RFC 3339
 * strings) and any custom claims. The key id of the issuing key is bound
 * into the footer. Opening and verifying check the token against
 * {@link Rules} and return the claims as JSON text, or throw a
 * {@link Cb2Exception} carrying the verdict.
 */
public final class Token {
    private Token() {
    }

    /**
     * Seals claimsJson under key as a cb2.local token.
     *
     * @param key the key
     * @param claimsJson the claims as a JSON object
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String seal(LocalKey key, String claimsJson) {
        return seal(key, claimsJson, null);
    }

    /**
     * Seals claimsJson under key with an implicit assertion.
     *
     * @param key the key
     * @param claimsJson the claims as a JSON object
     * @param implicit the implicit assertion, or null for none
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String seal(LocalKey key, String claimsJson, byte[] implicit) {
        byte[] c = Text.utf8(Text.required(claimsJson, "claimsJson"));
        return Text.string(Text.required(key, "key").handle.use(h -> Native.tokenSeal(h, c, implicit)));
    }

    /**
     * Signs claimsJson with key as a cb2.public token.
     *
     * @param key the signing pair
     * @param claimsJson the claims as a JSON object
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String sign(SecretKey key, String claimsJson) {
        return sign(key, claimsJson, null);
    }

    /**
     * Signs claimsJson with key and an implicit assertion.
     *
     * @param key the signing pair
     * @param claimsJson the claims as a JSON object
     * @param implicit the implicit assertion, or null for none
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String sign(SecretKey key, String claimsJson, byte[] implicit) {
        byte[] c = Text.utf8(Text.required(claimsJson, "claimsJson"));
        return Text.string(Text.required(key, "key").handle.use(h -> Native.tokenSign(h, c, implicit)));
    }

    /**
     * Opens a cb2.local token under key and checks it against rules.
     *
     * @param key the key
     * @param token the token
     * @param rules the rules
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String open(LocalKey key, String token, Rules rules) {
        return open(key, token, rules, null);
    }

    /**
     * Opens a cb2.local token under key with an implicit assertion and
     * checks it against rules.
     *
     * @param key the key
     * @param token the token
     * @param rules the rules
     * @param implicit the implicit assertion, or null for none
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String open(LocalKey key, String token, Rules rules, byte[] implicit) {
        byte[] t = Text.utf8(Text.required(token, "token"));
        byte[] r = Text.utf8(Text.required(rules, "rules").toJson());
        ReplayCheck replay = rules.replayCheck();
        ReplayCheck proofReplay = rules.proofReplayCheck();
        return Text.string(Text.required(key, "key").handle.use(
                h -> Native.tokenOpen(h, t, r, implicit, replay, proofReplay)));
    }

    /**
     * Verifies a cb2.public token with key and checks it against rules.
     *
     * @param key the public key
     * @param token the token
     * @param rules the rules
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String verify(PublicKey key, String token, Rules rules) {
        return verify(key, token, rules, null);
    }

    /**
     * Verifies a cb2.public token with key and an implicit assertion and
     * checks it against rules.
     *
     * @param key the public key
     * @param token the token
     * @param rules the rules
     * @param implicit the implicit assertion, or null for none
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String verify(PublicKey key, String token, Rules rules, byte[] implicit) {
        byte[] t = Text.utf8(Text.required(token, "token"));
        byte[] r = Text.utf8(Text.required(rules, "rules").toJson());
        ReplayCheck replay = rules.replayCheck();
        ReplayCheck proofReplay = rules.proofReplayCheck();
        return Text.string(Text.required(key, "key").handle.use(
                h -> Native.tokenVerify(h, t, r, implicit, replay, proofReplay)));
    }

    /**
     * The key id a token's footer names, read without verifying anything,
     * to pick the key to open or verify it with.
     *
     * @param token the token
     * @return the key id, or null when the footer names none
     * @throws Cb2Exception with {@link Code#INVALID} when the token is not
     *     well formed
     */
    public static String peekKeyId(String token) {
        return Text.string(Native.peekKeyId(Text.utf8(Text.required(token, "token"))));
    }
}
