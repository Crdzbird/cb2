package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.CLAIMS;
import static com.cipherbird.cb2.Support.bytes;
import static com.cipherbird.cb2.Support.expect;
import static com.cipherbird.cb2.Support.rules;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

class LocalTest {
    @Test
    void paserkShapeAndIds() {
        try (LocalKey k = LocalKey.generate()) {
            String paserk = k.toPaserk();
            assertTrue(paserk.startsWith("kcb2.local."), "local paserk prefix");
            assertEquals(54, paserk.length(), "local paserk length");
            String id = k.paserkId();
            assertTrue(id.startsWith("kcb2.lid."), "paserk id prefix");
            assertEquals(id, k.keyId(), "paserk id is the default key id");
            try (LocalKey same = LocalKey.fromPaserk(paserk)) {
                assertEquals(id, same.paserkId(), "paserk round trip keeps the id");
            }
        }
    }

    @Test
    void rawTokens() {
        try (LocalKey k = LocalKey.generate(); LocalKey same = LocalKey.fromPaserk(k.toPaserk())) {
            byte[] msg = bytes("hello");
            byte[] footer = bytes("{\"kid\":\"x\"}");
            String token = Local.seal(k, msg, footer);
            assertTrue(token.startsWith("cb2.local."), "local token prefix");
            assertArrayEquals(msg, Local.open(same, token, footer), "local round trip");
            expect(Code.INVALID, "open without the footer", () -> Local.open(same, token));
            char last = token.charAt(token.length() - 1);
            String tampered = token.substring(0, token.length() - 1) + (last == 'A' ? 'B' : 'A');
            expect(Code.INVALID, "open a tampered token", () -> Local.open(same, tampered, footer));
            expect(Code.TOO_LARGE, "open over the size limit", () -> Local.open(same, token, footer, null, 16));
        }
    }

    @Test
    void claimsTokens() {
        try (LocalKey k = LocalKey.generate()) {
            String ct = Token.seal(k, CLAIMS);
            String claims = Token.open(k, ct, rules());
            assertTrue(claims.contains("\"role\":\"admin\""), "custom claim comes back");
            assertTrue(claims.contains("\"jti\":\"id-1\""), "jti comes back");
            assertEquals(k.paserkId(), Token.peekKeyId(ct), "peeked key id");
            expect(Code.RULES_INCOMPLETE, "empty rules", () -> Token.open(k, ct, new Rules()));
            expect(Code.AUDIENCE_MISMATCH, "other audience", () -> Token.open(k, ct, rules().audience("other")));
            expect(Code.EXPIRED, "late clock", () -> Token.open(k, ct, rules().now(4102444801L)));
            expect(Code.LIFETIME_EXCEEDED, "max lifetime", () -> Token.open(k, ct, rules().maxLifetime(60)));
            expect(Code.ARGUMENT, "claims with a zero-width space", () -> Token.seal(k,
                    "{\"sub\":\"a\\u200bb\",\"exp\":\"2099-01-01T00:00:00+00:00\"}"));
        }
    }

    @Test
    void replayChecks() {
        try (LocalKey k = LocalKey.generate()) {
            String ct = Token.seal(k, CLAIMS);
            Set<String> seen = new HashSet<>();
            ReplayCheck remember = seen::add;
            Token.open(k, ct, rules().replay(remember));
            expect(Code.REPLAYED, "replayed via the callback", () -> Token.open(k, ct, rules().replay(remember)));
            expect(Code.REPLAYED, "replayed via seen_jti", () -> Token.open(k, ct, rules().seenJti("id-1")));
            expect(Code.REPLAYED, "a throwing check refuses", () -> Token.open(k, ct, rules().replay(jti -> {
                throw new IllegalStateException("store down");
            })));
        }
    }

    @Test
    void keyWrapping() {
        try (LocalKey k = LocalKey.generate(); LocalKey wrapping = LocalKey.generate()) {
            String wrapped = KeyWrap.wrap(wrapping, k);
            assertTrue(wrapped.startsWith("kcb2.local-wrap."), "wrapped prefix");
            assertEquals(144, wrapped.length(), "wrapped length");
            try (LocalKey unwrapped = KeyWrap.unwrap(wrapped, wrapping)) {
                assertEquals(k.paserkId(), unwrapped.paserkId(), "unwrapped key is the same key");
            }
            expect(Code.INVALID, "unwrap with the wrong key", () -> KeyWrap.unwrap(wrapped, k));
        }
    }

    @Test
    void keyIds() {
        try (LocalKey k = LocalKey.generate()) {
            k.setKeyId("rotation-1");
            assertEquals("rotation-1", k.keyId(), "key id set");
            assertEquals("rotation-1", Token.peekKeyId(Token.seal(k, CLAIMS)), "the footer carries the key id");
            expect(Code.ARGUMENT, "key id with a zero-width space", () -> k.setKeyId("a\u200b"));
            k.clearKeyId();
            assertNull(k.keyId(), "key id cleared");
        }
    }

    @Test
    void weakKeyBytes() {
        byte[] weak = new byte[32];
        Arrays.fill(weak, (byte) 7);
        expect(Code.ARGUMENT, "weak key bytes", () -> LocalKey.fromBytes(weak));
    }

    @Test
    void errorNames() {
        assertEquals("argument", Cb2.errorName(Code.ARGUMENT), "error names");
        assertEquals("ok", Cb2.errorName(Code.OK), "error names");
        assertEquals("proof_replayed", Cb2.errorName(Code.PROOF_REPLAYED), "error names at the edges");
        assertEquals("unknown", Cb2.errorName(99), "error names at the edges");
        assertTrue(!Cb2.version().isBlank(), "a version string");
    }
}
