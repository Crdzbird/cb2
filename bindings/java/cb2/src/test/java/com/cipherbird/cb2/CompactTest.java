package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.CLAIMS;
import static com.cipherbird.cb2.Support.NOW;
import static com.cipherbird.cb2.Support.TARGET;
import static com.cipherbird.cb2.Support.bound;
import static com.cipherbird.cb2.Support.bytes;
import static com.cipherbird.cb2.Support.expect;
import static com.cipherbird.cb2.Support.rules;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class CompactTest {
    private static final String FRACTION = "{\"iss\":\"https://issuer.example\",\"aud\":\"api\","
            + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"n\":1.5}";

    @Test
    void shorterWithTheSameClaims() {
        try (LocalKey k = LocalKey.generate()) {
            String compact = Compact.seal(k, CLAIMS);
            String full = Token.seal(k, CLAIMS);
            assertTrue(compact.startsWith("cb3.local."), "compact local prefix");
            assertTrue(compact.length() < full.length(), "compact is shorter than cb2");
            assertEquals(Token.open(k, full, rules()), Compact.open(k, compact, rules()), "the same claims");
            expect(Code.INVALID, "a compact token through Token", () -> Token.open(k, compact, rules()));
            expect(Code.INVALID, "a cb2 token through Compact", () -> Compact.open(k, full, rules()));
            expect(Code.INVALID, "another implicit assertion", () -> Compact.open(k, compact, rules(), bytes("x")));
            String bound = Compact.seal(k, CLAIMS, bytes("ctx"));
            assertTrue(Compact.open(k, bound, rules(), bytes("ctx")).contains("\"role\":\"admin\""), "implicit");
        }
    }

    @Test
    void verdicts() {
        try (LocalKey k = LocalKey.generate()) {
            String ct = Compact.seal(k, CLAIMS);
            expect(Code.RULES_INCOMPLETE, "empty rules", () -> Compact.open(k, ct, new Rules()));
            expect(Code.AUDIENCE_MISMATCH, "other audience", () -> Compact.open(k, ct, rules().audience("web")));
            expect(Code.EXPIRED, "late clock", () -> Compact.open(k, ct, rules().now(4102444800L)));
            expect(Code.REPLAYED, "replayed via seen_jti", () -> Compact.open(k, ct, rules().seenJti("id-1")));
            Set<String> seen = new HashSet<>();
            ReplayCheck remember = seen::add;
            Compact.open(k, ct, rules().replay(remember));
            expect(Code.REPLAYED, "replayed via the callback", () -> Compact.open(k, ct, rules().replay(remember)));
        }
    }

    @Test
    void keyDigests() {
        try (LocalKey k = LocalKey.generate()) {
            String ct = Compact.seal(k, CLAIMS);
            byte[] peeked = Compact.peekKeyDigest(ct);
            assertEquals(Compact.KEY_DIGEST_BYTES, peeked.length, "digest size");
            assertArrayEquals(Compact.keyDigest(k.keyId()), peeked, "peeked digest is the computed one");
            assertNull(Compact.peekKeyDigest(Token.seal(k, CLAIMS)), "a cb2 token carries no digest");
            expect(Code.ARGUMENT, "an id with a control character", () -> Compact.keyDigest("a\nb"));
            assertEquals(Compact.KEY_DIGEST_BYTES, Compact.keyDigest("").length, "the empty id has a digest");
            k.setKeyId("rotation-1");
            assertArrayEquals(Compact.keyDigest("rotation-1"), Compact.peekKeyDigest(Compact.seal(k, CLAIMS)),
                    "a set key id");
            k.clearKeyId();
            String bare = Compact.seal(k, CLAIMS);
            assertNull(Compact.peekKeyDigest(bare), "a key without an id");
            expect(Code.INVALID, "a token under the old id", () -> Compact.open(k, ct, rules()));
            assertTrue(Compact.open(k, bare, rules()).contains("\"sub\":\"user-1\""), "a key without an id opens");
            assertThrows(IllegalArgumentException.class, () -> Compact.keyDigest(null), "null id");
        }
    }

    @Test
    void profileRefusals() {
        try (LocalKey k = LocalKey.generate()) {
            expect(Code.ARGUMENT, "a fraction", () -> Compact.seal(k, FRACTION));
            assertTrue(Token.seal(k, FRACTION).startsWith("cb2.local."), "cb2 takes the fraction");
            expect(Code.ARGUMENT, "not JSON", () -> Compact.seal(k, "nope"));
            for (String n : new String[] {"1e3", "-0"}) {
                expect(Code.ARGUMENT, "the number " + n, () -> Compact.seal(k, FRACTION.replace("1.5", n)));
            }
            assertNotNull(Compact.seal(k, FRACTION.replace("1.5", "-9223372036854775808")), "int64 minimum");
        }
    }

    @Test
    void holderProof() {
        try (LocalKey k = LocalKey.generate(); LocalKey proofKey = LocalKey.generate()) {
            String cnf = proofKey.toPaserk();
            String access = Compact.seal(k, bound(cnf));
            expect(Code.MISSING_PROOF, "bound token without a proof", () -> Compact.open(k, access, rules()));
            String proof = Holder.proveLocal(proofKey, "GET", TARGET, null, access, "p-1", NOW, 60);
            String claims = Compact.open(k, access, rules().proof(proof).request("GET", TARGET)
                    .proofReplay(jti -> true));
            assertTrue(claims.contains(cnf), "the claims carry cnf");
            expect(Code.PROOF_MISMATCH, "a proof for another request", () -> Compact.open(k, access,
                    rules().proof(proof).request("POST", TARGET).proofSeenJti()));
        }
    }

    @Test
    void publicTokens() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build");
        try (SecretKey sk = SecretKey.generate(); PublicKey pk = sk.publicKey()) {
            String compact = Compact.sign(sk, CLAIMS);
            String full = Token.sign(sk, CLAIMS);
            assertTrue(compact.startsWith("cb3.public."), "compact public prefix");
            assertTrue(compact.length() < full.length(), "compact is shorter than cb2");
            assertEquals(Token.verify(pk, full, rules()), Compact.verify(pk, compact, rules()), "the same claims");
            expect(Code.INVALID, "a compact token through Token", () -> Token.verify(pk, compact, rules()));
            expect(Code.INVALID, "a cb2 token through Compact", () -> Compact.verify(pk, full, rules()));
            expect(Code.AUDIENCE_MISMATCH, "other audience", () -> Compact.verify(pk, compact, rules().audience("web")));
            assertArrayEquals(Compact.keyDigest(sk.keyId()), Compact.peekKeyDigest(compact), "signer digest");
            try (LocalKey proofKey = LocalKey.generate()) {
                String cnf = proofKey.toPaserk();
                expect(Code.ARGUMENT, "a signed token bound to a local proof key", () -> Compact.sign(sk, bound(cnf)));
            }
        }
    }
}
