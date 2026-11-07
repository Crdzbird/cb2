package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.CLAIMS;
import static com.cipherbird.cb2.Support.NOW;
import static com.cipherbird.cb2.Support.bytes;
import static com.cipherbird.cb2.Support.expect;
import static com.cipherbird.cb2.Support.rules;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClaimTableTest {
    private static final String[] ENTRIES = {"https://issuer.example", "api", "billing"};
    private static final String DIGEST = "767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d";

    @Test
    void refusedEntries() {
        expect(Code.ARGUMENT, "no entries", () -> ClaimTable.of());
        expect(Code.ARGUMENT, "a repeated entry", () -> ClaimTable.of("a", "a"));
        expect(Code.ARGUMENT, "an empty entry", () -> ClaimTable.of("a", ""));
        expect(Code.ARGUMENT, "a control character", () -> ClaimTable.of("a\nb"));
        List<String> many = new ArrayList<>();
        for (int i = 0; i < 257; i++) {
            many.add("e" + i);
        }
        expect(Code.ARGUMENT, "257 entries", () -> ClaimTable.of(many));
        try (ClaimTable full = ClaimTable.of(many.subList(0, 256))) {
            assertEquals(256, full.entries().size(), "256 entries");
        }
        assertThrows(IllegalArgumentException.class, () -> ClaimTable.of("a", null), "a null entry");
        assertThrows(IllegalArgumentException.class, () -> ClaimTable.of((List<String>) null), "a null list");
    }

    @Test
    void digests() {
        try (ClaimTable t = ClaimTable.of(ENTRIES);
                ClaimTable same = ClaimTable.of(Arrays.asList(ENTRIES));
                ClaimTable other = ClaimTable.of("api", "https://issuer.example", "billing")) {
            assertEquals(DIGEST, HexFormat.of().formatHex(t.digest()), "the known digest");
            assertEquals(ClaimTable.DIGEST_BYTES, t.digest().length, "digest size");
            assertArrayEquals(t.digest(), same.digest(), "the same entries give the same digest");
            assertFalse(Arrays.equals(t.digest(), other.digest()), "a reordered table differs");
            assertEquals(List.of(ENTRIES), t.entries(), "the entries in order");
            assertThrows(UnsupportedOperationException.class, () -> t.entries().add("x"), "entries are read-only");
        }
    }

    @Test
    void tabledTokens() {
        try (LocalKey k = LocalKey.generate();
                ClaimTable t = ClaimTable.of(ENTRIES);
                ClaimTable same = ClaimTable.of(ENTRIES);
                ClaimTable other = ClaimTable.of("api", "https://issuer.example", "billing")) {
            String tabled = Compact.seal(k, t, CLAIMS);
            String plain = Compact.seal(k, CLAIMS);
            assertTrue(tabled.startsWith("cb3.local."), "compact local prefix");
            assertTrue(tabled.length() + 30 < plain.length(), "a tabled token is shorter");
            assertEquals(Compact.open(k, plain, rules()), Compact.open(k, same, tabled, rules()), "the same claims");
            expect(Code.INVALID, "without the table", () -> Compact.open(k, tabled, rules()));
            expect(Code.INVALID, "a null table", () -> Compact.open(k, null, tabled, rules()));
            expect(Code.INVALID, "a reordered table", () -> Compact.open(k, other, tabled, rules()));
            expect(Code.INVALID, "a tableless token under the table", () -> Compact.open(k, t, plain, rules()));
            assertEquals(Compact.open(k, plain, rules()), Compact.open(k, null, plain, rules()), "null is no table");
            expect(Code.AUDIENCE_MISMATCH, "another entry as audience",
                    () -> Compact.open(k, t, tabled, rules().audience("billing")));
            expect(Code.ISSUER_MISMATCH, "another issuer",
                    () -> Compact.open(k, t, tabled, rules().issuer("https://other.example")));
            Rules any = new Rules().allowAnyIssuer(true).allowAnyAudience(true).now(NOW);
            assertTrue(Compact.open(k, t, tabled, any).contains("\"iss\":\"https://issuer.example\""), "allow any");
        }
    }

    @Test
    void reservedImplicit() {
        try (LocalKey k = LocalKey.generate(); ClaimTable t = ClaimTable.of(ENTRIES)) {
            byte[] reserved = bytes("kcb3.table.");
            String plain = Compact.seal(k, CLAIMS);
            expect(Code.ARGUMENT, "sealed without a table", () -> Compact.seal(k, CLAIMS, reserved));
            expect(Code.ARGUMENT, "sealed under a null table", () -> Compact.seal(k, null, CLAIMS, reserved));
            expect(Code.ARGUMENT, "opened without a table", () -> Compact.open(k, plain, rules(), reserved));
            String tabled = Compact.seal(k, t, CLAIMS, reserved);
            assertTrue(Compact.open(k, t, tabled, rules(), reserved).contains("\"role\":\"admin\""), "under a table");
        }
    }

    @Test
    void closedTable() {
        try (LocalKey k = LocalKey.generate()) {
            ClaimTable t = ClaimTable.of(ENTRIES);
            t.close();
            t.close();
            assertThrows(IllegalStateException.class, t::digest, "digest after close");
            assertThrows(IllegalStateException.class, () -> Compact.seal(k, t, CLAIMS), "seal after close");
        }
    }

    @Test
    void publicTokens() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build");
        try (SecretKey sk = SecretKey.generate();
                PublicKey pk = sk.publicKey();
                ClaimTable t = ClaimTable.of(ENTRIES);
                ClaimTable same = ClaimTable.of(ENTRIES);
                ClaimTable other = ClaimTable.of("api", "https://issuer.example", "billing")) {
            String tabled = Compact.sign(sk, t, CLAIMS);
            assertTrue(tabled.startsWith("cb3.public."), "compact public prefix");
            assertTrue(tabled.length() < Compact.sign(sk, CLAIMS).length(), "a tabled token is shorter");
            assertEquals(Compact.verify(pk, Compact.sign(sk, CLAIMS), rules()), Compact.verify(pk, same, tabled, rules()),
                    "the same claims");
            expect(Code.INVALID, "without the table", () -> Compact.verify(pk, tabled, rules()));
            expect(Code.INVALID, "a reordered table", () -> Compact.verify(pk, other, tabled, rules()));
        }
    }
}
