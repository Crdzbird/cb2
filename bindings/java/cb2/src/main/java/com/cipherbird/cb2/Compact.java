package com.cipherbird.cb2;

/**
 * Compact claims tokens, the experimental cb3.local and cb3.public
 * formats of docs/PROTOCOL.md section 15. They take and return the same
 * claims JSON and {@link Rules} as {@link Token}, with the same
 * cryptography and the same verdicts, but carry the claims as strict
 * CBOR and bind the key id as a {@value #KEY_DIGEST_BYTES}-byte digest
 * instead of its text, so a typical token is about half the size. The
 * issuer refuses with {@link Code#ARGUMENT} what the compact profile
 * cannot carry: a custom number that is not an integer in the signed
 * 64-bit range written in canonical form (1.5, 1e3 and -0 are refused),
 * a time outside years 0000 to 9999, and a cnf that is not a kcb2.local
 * or kcb2.public key. A cb2 token never opens here and a compact token
 * never opens through {@link Token}. Holder proofs bind a compact access
 * token exactly as they bind a cb2 one.
 */
public final class Compact {
    /** The size in bytes of the key digest a compact token's footer carries. */
    public static final int KEY_DIGEST_BYTES = 16;

    private Compact() {
    }

    /**
     * Seals claimsJson under key as a compact local token.
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
     * Seals claimsJson under key with an implicit assertion as a compact
     * local token.
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
        return Text.string(Text.required(key, "key").handle.use(h -> Native.compactSeal(h, c, implicit)));
    }

    /**
     * Signs claimsJson with key as a compact public token.
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
     * Signs claimsJson with key and an implicit assertion as a compact
     * public token.
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
        return Text.string(Text.required(key, "key").handle.use(h -> Native.compactSign(h, c, implicit)));
    }

    /**
     * Opens a compact local token under key and checks it against rules.
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
     * Opens a compact local token under key with an implicit assertion and
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
                h -> Native.compactOpen(h, t, r, implicit, replay, proofReplay)));
    }

    /**
     * Verifies a compact public token with key and checks it against
     * rules.
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
     * Verifies a compact public token with key and an implicit assertion
     * and checks it against rules.
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
                h -> Native.compactVerify(h, t, r, implicit, replay, proofReplay)));
    }

    /**
     * The key digest a compact token's footer carries, read without
     * verifying anything, to pick the key to open or verify it with:
     * compare it with {@link #keyDigest(String)} of each key id.
     *
     * @param token the token
     * @return the {@value #KEY_DIGEST_BYTES}-byte digest, or null when the
     *     token carries none (a key without an id, or a token that is not
     *     compact)
     * @throws Cb2Exception with {@link Code#INVALID} when the token is not
     *     well formed
     */
    public static byte[] peekKeyDigest(String token) {
        return Native.compactPeekKeyDigest(Text.utf8(Text.required(token, "token")));
    }

    /**
     * The digest a compact token's footer carries for a key with this key
     * id, such as {@link LocalKey#keyId()}. The empty id has a digest too.
     *
     * @param keyId the key id
     * @return the {@value #KEY_DIGEST_BYTES}-byte digest
     * @throws Cb2Exception with {@link Code#ARGUMENT} when the id holds
     *     control characters or is otherwise not a valid key id
     */
    public static byte[] keyDigest(String keyId) {
        return Native.compactKeyDigest(Text.utf8(Text.required(keyId, "keyId")));
    }
}
