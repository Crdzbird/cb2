package com.cipherbird.cb2;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * The Java bridge exercised the way test_c.c exercises the C ABI: keys,
 * raw tokens, claims tokens with rules and both replay checks, a holder
 * proof, key wrapping and sealing, and every verdict. Throws on the
 * first failed check.
 */
public final class Cb2Test {
    private static final String CLAIMS = "{\"iss\":\"https://issuer.example\",\"sub\":\"user-1\",\"aud\":\"api\","
            + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\",\"role\":\"admin\"}";

    private Cb2Test() {
    }

    private static void check(boolean condition, String what) {
        if (!condition) {
            throw new AssertionError("FAIL " + what);
        }
    }

    private static void expect(int code, String what, Runnable action) {
        try {
            action.run();
        } catch (Cb2Exception e) {
            check(e.code() == code, what + ": expected " + Cb2.errorName(code) + ", got " + e.name());
            return;
        }
        throw new AssertionError("FAIL " + what + ": expected " + Cb2.errorName(code) + ", got ok");
    }

    private static Rules rules() {
        return new Rules().issuer("https://issuer.example").audience("api").now(1700000000L);
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static void testLocal() {
        try (LocalKey k = LocalKey.generate()) {
            String paserk = k.toPaserk();
            check(paserk.startsWith("kcb2.local.") && paserk.length() == 54, "local paserk shape");
            String id = k.paserkId();
            check(id.equals(k.keyId()) && id.startsWith("kcb2.lid."), "paserk id is the default key id");
            try (LocalKey same = LocalKey.fromPaserk(paserk)) {
                check(id.equals(same.paserkId()), "paserk round trip keeps the id");

                byte[] msg = bytes("hello");
                byte[] footer = bytes("{\"kid\":\"x\"}");
                String token = Local.seal(k, msg, footer);
                check(token.startsWith("cb2.local."), "local token prefix");
                check(Arrays.equals(Local.open(same, token, footer), msg), "local round trip");
                expect(Code.INVALID, "open without the footer", () -> Local.open(same, token));
                char last = token.charAt(token.length() - 1);
                String tampered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
                expect(Code.INVALID, "open a tampered token", () -> Local.open(same, tampered, footer));
            }

            String ct = Token.seal(k, CLAIMS);
            String claims = Token.open(k, ct, rules());
            check(claims.contains("\"role\":\"admin\"") && claims.contains("\"jti\":\"id-1\""), "claims come back");
            check(id.equals(Token.peekKeyId(ct)), "peeked key id");
            expect(Code.RULES_INCOMPLETE, "empty rules", () -> Token.open(k, ct, new Rules()));
            expect(Code.AUDIENCE_MISMATCH, "other audience", () -> Token.open(k, ct, rules().audience("other")));
            expect(Code.EXPIRED, "late clock", () -> Token.open(k, ct, rules().now(4102444801L)));

            Set<String> seen = new HashSet<>();
            ReplayCheck remember = seen::add;
            Token.open(k, ct, rules().replay(remember));
            expect(Code.REPLAYED, "replayed via the callback", () -> Token.open(k, ct, rules().replay(remember)));
            expect(Code.REPLAYED, "replayed via seen_jti", () -> Token.open(k, ct, rules().seenJti("id-1")));
            expect(Code.REPLAYED, "a throwing check refuses", () -> Token.open(k, ct, rules().replay(jti -> {
                throw new IllegalStateException("store down");
            })));
            expect(Code.LIFETIME_EXCEEDED, "max lifetime", () -> Token.open(k, ct, rules().maxLifetime(60)));
            expect(Code.ARGUMENT, "claims with a zero-width space", () -> Token.seal(k,
                    "{\"sub\":\"a\\u200bb\",\"exp\":\"2099-01-01T00:00:00+00:00\"}"));

            try (LocalKey wrapping = LocalKey.generate()) {
                String wrapped = KeyWrap.wrap(wrapping, k);
                check(wrapped.startsWith("kcb2.local-wrap.") && wrapped.length() == 144, "wrapped shape");
                try (LocalKey unwrapped = KeyWrap.unwrap(wrapped, wrapping)) {
                    check(id.equals(unwrapped.paserkId()), "unwrapped key is the same key");
                }
                expect(Code.INVALID, "unwrap with the wrong key", () -> KeyWrap.unwrap(wrapped, k));
            }

            k.setKeyId("rotation-1");
            check("rotation-1".equals(k.keyId()), "key id set");
            expect(Code.ARGUMENT, "key id with a zero-width space", () -> k.setKeyId("a\u200b"));
            k.clearKeyId();
            check(k.keyId() == null, "key id cleared");
        }
        byte[] weak = new byte[32];
        Arrays.fill(weak, (byte) 7);
        expect(Code.ARGUMENT, "weak key bytes", () -> LocalKey.fromBytes(weak));
        check("argument".equals(Cb2.errorName(Code.ARGUMENT)) && "ok".equals(Cb2.errorName(0)), "error names");
        check("proof_replayed".equals(Cb2.errorName(Code.PROOF_REPLAYED)) && "unknown".equals(Cb2.errorName(99)),
                "error names at the edges");
    }

    private static void testPublic() {
        if (!Cb2.hasPublic()) {
            System.out.println("cb2.public unavailable in this build; skipping");
            return;
        }
        try (SecretKey sk = SecretKey.generate();
                PublicKey pk = sk.publicKey();
                SecretKey stranger = SecretKey.generate();
                PublicKey spk = stranger.publicKey();
                LocalKey k = LocalKey.generate()) {
            String pub = pk.toPaserk();
            check(pub.length() == 2658, "public paserk length");
            try (PublicKey pk2 = PublicKey.fromPaserk(pub)) {
                String token = Token.sign(sk, CLAIMS);
                String claims = Token.verify(pk2, token, rules());
                check(claims.contains("\"sub\":\"user-1\""), "verified claims");
                expect(Code.INVALID, "verify with a stranger's key", () -> Token.verify(spk, token, rules()));
                String raw = Public.sign(sk, bytes("raw"), bytes("f"));
                check(Arrays.equals(Public.verify(pk2, raw, bytes("f")), bytes("raw")),
                        "raw public round trip");
            }

            String bound = "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":\"2099-01-01T00:00:00+00:00\","
                    + "\"cnf\":" + Json.quote(spk.toPaserk()) + "}";
            String access = Token.seal(k, bound);
            expect(Code.MISSING_PROOF, "bound token without a proof", () -> Token.open(k, access, rules()));
            String proof = Holder.prove(stranger, "GET", "https://api.example/v1/me", null, access, "p-1", 1700000000L, 60);
            check(proof.startsWith("cb2.holder-public."), "proof prefix");
            Rules presented = rules().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1");
            expect(Code.RULES_INCOMPLETE, "proof without a proof replay check", () -> Token.open(k, access, presented));
            Token.open(k, access, presented.proofReplay(jti -> true));
            expect(Code.PROOF_MISMATCH, "proof for another request", () -> Token.open(k, access,
                    rules().proof(proof).request("POST", "https://api.example/v1/me").proofSeenJti()));
            expect(Code.PROOF_REPLAYED, "proof id already seen", () -> Token.open(k, access,
                    rules().proof(proof).request("GET", "https://api.example/v1/me").proofSeenJti("p-1")));
            expect(Code.PROOF_REPLAYED, "proof refused by the callback", () -> Token.open(k, access,
                    rules().proof(proof).request("GET", "https://api.example/v1/me").proofReplay(jti -> false)));
            expect(Code.PROOF_EXPIRED, "proof too old", () -> Token.open(k, access,
                    rules().now(1700000100L).proof(proof).request("GET", "https://api.example/v1/me").proofSeenJti()));
            Token.open(k, access, rules().ignoreCnf(true));
            check("https://api.example/a".equals(Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c")), "normalised target");
            expect(Code.ARGUMENT, "normalise a non-target", () -> Holder.normalizeTarget("nope"));
        }
    }

    private static void testSeal() {
        if (!Cb2.hasSeal()) {
            System.out.println("kcb2.seal unavailable in this build; skipping");
            return;
        }
        try (RecipientKey r = RecipientKey.generate();
                RecipientPublicKey rp = r.publicKey();
                LocalKey k = LocalKey.generate();
                RecipientKey other = RecipientKey.generate()) {
            String rec = rp.toPaserk();
            check(rec.length() == 1637 && rec.startsWith("kcb2.recipient."), "recipient paserk shape");
            String secret = r.toPaserk();
            check(secret.length() == 65, "recipient secret length");
            try (RecipientKey r2 = RecipientKey.fromPaserk(secret)) {
                String sealed = Seal.seal(rp, k);
                check(sealed.length() == 1632, "sealed length");
                try (LocalKey back = Seal.unseal(sealed, r2)) {
                    check(k.paserkId().equals(back.paserkId()), "unsealed key is the same key");
                }
                expect(Code.INVALID, "unseal by another recipient", () -> Seal.unseal(sealed, other));
                check(rp.paserkId().equals(r2.paserkId()) && rp.paserkId().startsWith("kcb2.rid."), "recipient ids");
            }
        }
    }

    private static void testClosed() {
        LocalKey k = LocalKey.generate();
        k.close();
        k.close();
        try {
            k.paserkId();
        } catch (IllegalStateException e) {
            return;
        }
        throw new AssertionError("FAIL a closed key must refuse use");
    }

    public static void main(String[] args) {
        System.out.println("cb2 " + Cb2.version() + ", public " + Cb2.hasPublic() + ", seal " + Cb2.hasSeal());
        testLocal();
        testPublic();
        testSeal();
        testClosed();
        System.out.println("Cb2Test: all checks passed");
    }
}
