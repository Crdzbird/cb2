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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PublicTest {
    @BeforeEach
    void requirePublic() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build");
    }

    @Test
    void signAndVerify() {
        try (SecretKey sk = SecretKey.generate();
                PublicKey pk = sk.publicKey();
                SecretKey stranger = SecretKey.generate();
                PublicKey spk = stranger.publicKey()) {
            String pub = pk.toPaserk();
            assertEquals(2658, pub.length(), "public paserk length");
            try (PublicKey pk2 = PublicKey.fromPaserk(pub)) {
                String token = Token.sign(sk, CLAIMS);
                assertTrue(Token.verify(pk2, token, rules()).contains("\"sub\":\"user-1\""), "verified claims");
                expect(Code.INVALID, "verify with a stranger's key", () -> Token.verify(spk, token, rules()));
                String raw = Public.sign(sk, bytes("raw"), bytes("f"));
                assertArrayEquals(bytes("raw"), Public.verify(pk2, raw, bytes("f")), "raw public round trip");
                expect(Code.INVALID, "raw verify without the footer", () -> Public.verify(pk2, raw));
            }
            try (SecretKey again = SecretKey.fromPaserk(sk.toPaserk()); PublicKey pk3 = again.publicKey()) {
                assertEquals(pk.paserkId(), pk3.paserkId(), "secret paserk round trip keeps the pair");
            }
        }
    }

    @Test
    void publicModeProofs() {
        try (SecretKey stranger = SecretKey.generate();
                PublicKey spk = stranger.publicKey();
                LocalKey k = LocalKey.generate()) {
            String access = Token.seal(k, bound(spk.toPaserk()));
            expect(Code.MISSING_PROOF, "bound token without a proof", () -> Token.open(k, access, rules()));
            String proof = Holder.prove(stranger, "GET", TARGET, null, access, "p-1", NOW, 60);
            assertTrue(proof.startsWith("cb2.holder-public."), "proof prefix");
            Rules presented = rules().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1");
            expect(Code.RULES_INCOMPLETE, "proof without a proof replay check", () -> Token.open(k, access, presented));
            Token.open(k, access, presented.proofReplay(jti -> true));
            expect(Code.PROOF_MISMATCH, "proof for another request", () -> Token.open(k, access,
                    rules().proof(proof).request("POST", TARGET).proofSeenJti()));
            expect(Code.PROOF_REPLAYED, "proof id already seen", () -> Token.open(k, access,
                    rules().proof(proof).request("GET", TARGET).proofSeenJti("p-1")));
            expect(Code.PROOF_REPLAYED, "proof refused by the callback", () -> Token.open(k, access,
                    rules().proof(proof).request("GET", TARGET).proofReplay(jti -> false)));
            expect(Code.PROOF_EXPIRED, "proof too old", () -> Token.open(k, access,
                    rules().now(NOW + 100).proof(proof).request("GET", TARGET).proofSeenJti()));
            Token.open(k, access, rules().ignoreCnf(true));
        }
    }

    @Test
    void targetNormalisation() {
        assertEquals("https://api.example/a", Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c"), "normalised target");
        expect(Code.ARGUMENT, "normalise a non-target", () -> Holder.normalizeTarget("nope"));
    }
}
