package com.cipherbird.cb2;

/**
 * Claims tokens. Claims are JSON text: an object with the registered
 * claims as strings (times as RFC 3339) and any custom claims; the key
 * id of the issuing key is bound into the footer. Opening and verifying
 * take a {@link Rules} and return the claims as JSON text, or throw a
 * {@link Cb2Exception} carrying the verdict.
 */
public final class Token {
    private Token() {
    }

    /** Seals claimsJson under key. */
    public static String seal(LocalKey key, String claimsJson) {
        return seal(key, claimsJson, null);
    }

    /** Seals claimsJson under key with an implicit assertion. */
    public static String seal(LocalKey key, String claimsJson, byte[] implicit) {
        return Text.string(Native.tokenSeal(key.handle(), Text.utf8(Text.required(claimsJson, "claimsJson")), implicit));
    }

    /** Signs claimsJson with key. */
    public static String sign(SecretKey key, String claimsJson) {
        return sign(key, claimsJson, null);
    }

    /** Signs claimsJson with key and an implicit assertion. */
    public static String sign(SecretKey key, String claimsJson, byte[] implicit) {
        return Text.string(Native.tokenSign(key.handle(), Text.utf8(Text.required(claimsJson, "claimsJson")), implicit));
    }

    /** Opens token under key against rules and returns the claims JSON. */
    public static String open(LocalKey key, String token, Rules rules) {
        return open(key, token, rules, null);
    }

    /** Opens token under key against rules with an implicit assertion and returns the claims JSON. */
    public static String open(LocalKey key, String token, Rules rules, byte[] implicit) {
        requireRules(rules);
        return Text.string(Native.tokenOpen(key.handle(), Text.utf8(Text.required(token, "token")),
                Text.utf8(rules.toJson()), implicit, rules.replayCheck(), rules.proofReplayCheck()));
    }

    /** Verifies token with key against rules and returns the claims JSON. */
    public static String verify(PublicKey key, String token, Rules rules) {
        return verify(key, token, rules, null);
    }

    /** Verifies token with key against rules with an implicit assertion and returns the claims JSON. */
    public static String verify(PublicKey key, String token, Rules rules, byte[] implicit) {
        requireRules(rules);
        return Text.string(Native.tokenVerify(key.handle(), Text.utf8(Text.required(token, "token")),
                Text.utf8(rules.toJson()), implicit, rules.replayCheck(), rules.proofReplayCheck()));
    }

    private static void requireRules(Rules rules) {
        if (rules == null) {
            throw new IllegalArgumentException("rules must not be null");
        }
    }

    /** The key id a token's footer names, unverified; null when it names none. */
    public static String peekKeyId(String token) {
        return Text.string(Native.peekKeyId(Text.utf8(Text.required(token, "token"))));
    }
}
