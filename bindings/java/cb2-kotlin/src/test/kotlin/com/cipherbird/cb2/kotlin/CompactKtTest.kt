package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.Compact
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.SecretKey
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class CompactKtTest {
    @Test
    fun shorterWithTheSameClaims() {
        LocalKey.generate().use { k ->
            val compact = k.sealCompact(CLAIMS)
            val full = k.sealClaims(CLAIMS)
            assertTrue(compact.startsWith("cb3.local.") && compact.length < full.length, "compact local shape")
            assertEquals(k.openClaims(full, base()), k.openCompact(compact, base()), "the same claims")
            assertEquals(k.openCompact(compact, base()), k.openCompact(k.sealCompact(CLAIMS.toClaimsJson()), base()), "map and JSON")
            expect("invalid", "a compact token through openClaims") { k.openClaims(compact, base()) }
            expect("invalid", "a cb2 token through openCompact") { k.openCompact(full, base()) }
        }
    }

    @Test
    fun verdicts() {
        LocalKey.generate().use { k ->
            val ct = k.sealCompact(CLAIMS)
            expect("rules_incomplete", "empty rules") { k.openCompact(ct) {} }
            expect("audience_mismatch", "other audience") {
                k.openCompact(ct) {
                    issuer("https://issuer.example")
                    audience("web")
                    now(NOW)
                }
            }
            expect("expired", "late clock") { k.openCompact(ct, base().now(4102444800L)) }
            expect("replayed", "replayed via seen_jti") { k.openCompact(ct, base().seenJti("id-1")) }
            val seen = mutableSetOf<String>()
            k.openCompact(ct, base().onReplay { seen.add(it) })
            expect("replayed", "replayed via the lambda") { k.openCompact(ct, base().onReplay { seen.add(it) }) }
        }
    }

    @Test
    fun keyDigests() {
        LocalKey.generate().use { k ->
            val ct = k.sealCompact(CLAIMS)
            val peeked = ct.peekCompactKeyDigest()
            assertEquals(Compact.KEY_DIGEST_BYTES, peeked?.size, "digest size")
            assertArrayEquals(k.compactKeyDigest, peeked, "peeked digest is the key's digest")
            assertNull(k.sealClaims(CLAIMS).peekCompactKeyDigest(), "a cb2 token carries no digest")
            expect("argument", "an id with a control character") { Compact.keyDigest("a\nb") }
            k.clearKeyId()
            assertNull(k.compactKeyDigest, "a key without an id has no digest")
            val bare = k.sealCompact(CLAIMS)
            assertNull(bare.peekCompactKeyDigest(), "a token under a key without an id")
            expect("invalid", "a token under the old id") { k.openCompact(ct, base()) }
            assertTrue("\"sub\":\"user-1\"" in k.openCompact(bare, base()), "a key without an id opens")
        }
    }

    @Test
    fun fractionRefused() {
        LocalKey.generate().use { k ->
            val fraction = claims("iss" to "https://issuer.example", "aud" to "api", "exp" to EXP, "n" to 1.5)
            expect("argument", "a fraction") { k.sealCompact(fraction) }
            assertTrue(k.sealClaims(fraction).startsWith("cb2.local."), "cb2 takes the fraction")
            assertTrue(k.sealCompact(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to EXP, "n" to 15L)).startsWith("cb3.local."), "an integer")
        }
    }

    @Test
    fun holderProof() {
        LocalKey.generate().use { k ->
            LocalKey.generate().use { proofKey ->
                val cnf = proofKey.toPaserk()
                val access = k.sealCompact(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to EXP, "cnf" to cnf))
                expect("missing_proof", "bound token without a proof") { k.openCompact(access, base()) }
                val proof = proofKey.prove("GET", TARGET, access, "p-1", NOW)
                val proofs = mutableSetOf<String>()
                assertTrue(cnf in k.openCompact(access, base().proof(proof).request("GET", TARGET).onProofReplay { proofs.add(it) }), "the claims carry cnf")
                expect("proof_mismatch", "a proof for another request") {
                    k.openCompact(access, base().proof(proof).request("POST", TARGET).proofSeenJti())
                }
            }
        }
    }

    @Test
    fun publicTokens() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build")
        SecretKey.generate().use { sk ->
            sk.publicKey().use { pk ->
                val compact = sk.signCompact(CLAIMS)
                val full = sk.signClaims(CLAIMS)
                assertTrue(compact.startsWith("cb3.public.") && compact.length < full.length, "compact public shape")
                assertEquals(pk.verifyClaims(full, base()), pk.verifyCompact(compact, base()), "the same claims")
                expect("invalid", "a compact token through verifyClaims") { pk.verifyClaims(compact, base()) }
                expect("invalid", "a cb2 token through verifyCompact") { pk.verifyCompact(full, base()) }
                expect("audience_mismatch", "other audience") {
                    pk.verifyCompact(compact) {
                        issuer("https://issuer.example")
                        audience("web")
                        now(NOW)
                    }
                }
                assertArrayEquals(sk.compactKeyDigest, compact.peekCompactKeyDigest(), "signer digest")
                assertArrayEquals(pk.compactKeyDigest, compact.peekCompactKeyDigest(), "verifier digest")
            }
        }
    }
}
