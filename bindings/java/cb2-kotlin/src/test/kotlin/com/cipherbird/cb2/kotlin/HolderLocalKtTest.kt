package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.LocalKey
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class HolderLocalKtTest {
    @Test
    fun localModeProofs() {
        LocalKey.generate().use { k ->
            LocalKey.generate().use { issued ->
                val cnf = issued.toPaserk()
                val access = k.sealClaims(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to EXP, "cnf" to cnf))
                expect("missing_proof", "local-bound token without a proof") { k.openClaims(access, base()) }
                LocalKey.fromPaserk(cnf).use { client ->
                    val proof = client.prove("GET", TARGET, access, "p-1", NOW)
                    assertTrue(proof.startsWith("cb2.holder-local."), "local proof prefix")
                    val proofs = mutableSetOf<String>()
                    k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1").onProofReplay { proofs.add(it) })
                    expect("proof_replayed", "local proof id already seen by the lambda") {
                        k.openClaims(access, base().proof(proof).request("GET", TARGET).onProofReplay { proofs.add(it) })
                    }
                    expect("proof_mismatch", "local proof for another request") {
                        k.openClaims(access, base().proof(proof).request("POST", TARGET).proofSeenJti())
                    }
                }
                LocalKey.generate().use { stranger ->
                    val forged = stranger.prove("GET", TARGET, access, "p-2", NOW)
                    expect("proof_invalid", "local proof under another key") {
                        k.openClaims(access, base().proof(forged).request("GET", TARGET).proofSeenJti())
                    }
                }
            }
        }
    }
}
