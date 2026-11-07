package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.Cb2Exception
import com.cipherbird.cb2.Holder
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.PublicKey
import com.cipherbird.cb2.SecretKey
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class PublicKtTest {
    @BeforeEach
    fun requirePublic() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build")
    }

    @Test
    fun signAndVerify() {
        SecretKey.generate().use { sk ->
            sk.publicKey().use { pk ->
                SecretKey.generate().use { stranger ->
                    stranger.publicKey().use { spk ->
                        assertEquals(2658, pk.toPaserk().length, "public paserk length")
                        val token = sk.signClaims(CLAIMS)
                        assertTrue("\"sub\":\"user-1\"" in pk.verifyClaims(token, base()), "verified claims")
                        expect("invalid", "verify with a stranger's key") {
                            spk.verifyClaims(token) {
                                issuer("https://issuer.example")
                                audience("api")
                                now(NOW)
                            }
                        }
                        val raw = sk.sign("raw".toByteArray())
                        assertArrayEquals("raw".toByteArray(), pk.verify(raw), "raw public round trip")
                    }
                }
            }
        }
    }

    @Test
    fun publicModeProofs() {
        SecretKey.generate().use { stranger ->
            stranger.publicKey().use { spk -> LocalKey.generate().use { k -> bound(stranger, spk, k) } }
        }
    }

    private fun bound(stranger: SecretKey, spk: PublicKey, k: LocalKey) {
        val access = k.sealClaims(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to EXP, "cnf" to spk.toPaserk()))
        expect("missing_proof", "bound token without a proof") { k.openClaims(access, base()) }
        val proof = stranger.prove("GET", TARGET, access, "p-1", NOW)
        assertTrue(proof.startsWith("cb2.holder-public."), "proof prefix")
        expect("rules_incomplete", "proof without a proof replay check") {
            k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1"))
        }
        val proofs = mutableSetOf<String>()
        k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1").onProofReplay { proofs.add(it) })
        expect("proof_replayed", "proof id already seen by the lambda") {
            k.openClaims(access, base().proof(proof).request("GET", TARGET).onProofReplay { proofs.add(it) })
        }
        expect("proof_mismatch", "proof for another request") {
            k.openClaims(access, base().proof(proof).request("POST", TARGET).proofSeenJti())
        }
        expect("proof_replayed", "proof id in proof_seen_jti") {
            k.openClaims(access, base().proof(proof).request("GET", TARGET).proofSeenJti("p-1"))
        }
        expect("proof_expired", "proof too old") {
            k.openClaims(access, base().now(NOW + 100).proof(proof).request("GET", TARGET).proofSeenJti())
        }
        k.openClaims(access, base().ignoreCnf(true))
        assertEquals("https://api.example/a", Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c"), "normalised target")
        expect("argument", "normalise a non-target") { Holder.normalizeTarget("nope") }
        val e = assertThrows(Cb2Exception::class.java) { k.openClaims(access, base()) }
        assertEquals(19, e.code(), "exception carries the code")
        assertEquals("missing_proof", e.verdict, "exception carries the name")
        assertEquals("cb2: missing_proof (19)", e.message, "exception message")
    }
}
