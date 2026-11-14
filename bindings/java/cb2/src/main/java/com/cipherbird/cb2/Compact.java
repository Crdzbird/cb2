package com.cipherbird.cb2;

import java.util.function.LongFunction;

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
 *
 * <p>Every call has an overload that takes a {@link ClaimTable} after the
 * key, which shortens iss and aud; a token made under a table opens only
 * under the same table, and a null table means none. Without a table, an
 * implicit assertion that starts with {@code kcb3.table.} is refused with
 * {@link Code#ARGUMENT}.
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
        return seal(key, null, claimsJson, implicit);
    }

    /**
     * Seals claimsJson under key and table as a compact local token.
     *
     * @param key the key
     * @param table the claim table, or null for none
     * @param claimsJson the claims as a JSON object
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String seal(LocalKey key, ClaimTable table, String claimsJson) {
        return seal(key, table, claimsJson, null);
    }

    /**
     * Seals claimsJson under key and table with an implicit assertion as a
     * compact local token.
     *
     * @param key the key
     * @param table the claim table, or null for none
     * @param claimsJson the claims as a JSON object
     * @param implicit the implicit assertion, or null for none
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String seal(LocalKey key, ClaimTable table, String claimsJson, byte[] implicit) {
        byte[] c = Text.utf8(Text.required(claimsJson, "claimsJson"));
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(withTable(table, t -> k.use(h -> Native.compactSeal(h, t, c, implicit))));
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
        return sign(key, null, claimsJson, implicit);
    }

    /**
     * Signs claimsJson with key under table as a compact public token.
     *
     * @param key the signing pair
     * @param table the claim table, or null for none
     * @param claimsJson the claims as a JSON object
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String sign(SecretKey key, ClaimTable table, String claimsJson) {
        return sign(key, table, claimsJson, null);
    }

    /**
     * Signs claimsJson with key under table and an implicit assertion as a
     * compact public token.
     *
     * @param key the signing pair
     * @param table the claim table, or null for none
     * @param claimsJson the claims as a JSON object
     * @param implicit the implicit assertion, or null for none
     * @return the token
     * @throws Cb2Exception with {@link Code#CLAIMS_MALFORMED} or
     *     {@link Code#ARGUMENT} when the claims are refused
     */
    public static String sign(SecretKey key, ClaimTable table, String claimsJson, byte[] implicit) {
        byte[] c = Text.utf8(Text.required(claimsJson, "claimsJson"));
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(withTable(table, t -> k.use(h -> Native.compactSign(h, t, c, implicit))));
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
        return open(key, null, token, rules, implicit);
    }

    /**
     * Opens a compact local token under key and table and checks it
     * against rules.
     *
     * @param key the key
     * @param table the claim table, or null for none
     * @param token the token
     * @param rules the rules
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String open(LocalKey key, ClaimTable table, String token, Rules rules) {
        return open(key, table, token, rules, null);
    }

    /**
     * Opens a compact local token under key and table with an implicit
     * assertion and checks it against rules.
     *
     * @param key the key
     * @param table the claim table, or null for none
     * @param token the token
     * @param rules the rules
     * @param implicit the implicit assertion, or null for none
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String open(LocalKey key, ClaimTable table, String token, Rules rules, byte[] implicit) {
        byte[] tk = Text.utf8(Text.required(token, "token"));
        byte[] r = Text.utf8(Text.required(rules, "rules").toJson());
        ReplayCheck replay = rules.replayCheck();
        ReplayCheck proofReplay = rules.proofReplayCheck();
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(withTable(table, t -> k.use(
                h -> Native.compactOpen(h, t, tk, r, implicit, replay, proofReplay))));
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
        return verify(key, null, token, rules, implicit);
    }

    /**
     * Verifies a compact public token with key under table and checks it
     * against rules.
     *
     * @param key the public key
     * @param table the claim table, or null for none
     * @param token the token
     * @param rules the rules
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String verify(PublicKey key, ClaimTable table, String token, Rules rules) {
        return verify(key, table, token, rules, null);
    }

    /**
     * Verifies a compact public token with key under table and an implicit
     * assertion and checks it against rules.
     *
     * @param key the public key
     * @param table the claim table, or null for none
     * @param token the token
     * @param rules the rules
     * @param implicit the implicit assertion, or null for none
     * @return the claims as JSON text
     * @throws Cb2Exception carrying the verdict when the token is refused
     */
    public static String verify(PublicKey key, ClaimTable table, String token, Rules rules, byte[] implicit) {
        byte[] tk = Text.utf8(Text.required(token, "token"));
        byte[] r = Text.utf8(Text.required(rules, "rules").toJson());
        ReplayCheck replay = rules.replayCheck();
        ReplayCheck proofReplay = rules.proofReplayCheck();
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(withTable(table, t -> k.use(
                h -> Native.compactVerify(h, t, tk, r, implicit, replay, proofReplay))));
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

    private static <T> T withTable(ClaimTable table, LongFunction<T> call) {
        if (table == null) {
            return call.apply(0);
        }
        return table.handle.use(call);
    }
}
