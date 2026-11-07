package com.cipherbird.cb2.example.tour

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.SecretKey
import com.cipherbird.cb2.kotlin.claims
import com.cipherbird.cb2.kotlin.openClaims
import com.cipherbird.cb2.kotlin.rememberingCheck
import com.cipherbird.cb2.kotlin.sealClaims
import com.cipherbird.cb2.kotlin.signClaims
import com.cipherbird.cb2.kotlin.verdictOf
import com.cipherbird.cb2.kotlin.verifyClaims
import java.time.Instant

/** The quick start of the README: a cb2.local token, a refusal, and a cb2.public token. */
fun main() {
    val claims = claims(
        "iss" to "https://issuer.example",
        "aud" to "api",
        "sub" to "user-1",
        "exp" to Instant.now().plusSeconds(3600),
        "jti" to "id-1",
    )
    val seen = rememberingCheck()

    LocalKey.generate().use { key ->
        val token = key.sealClaims(claims)
        println("cb2.local token: ${token.length} chars")
        println("opened:          " + key.openClaims(token) { issuer("https://issuer.example"); audience("api"); replay(seen) })
        val again = verdictOf { key.openClaims(token) { issuer("https://issuer.example"); audience("api"); replay(seen) } }
        println("opened again:    refused, $again")
    }

    if (Cb2.hasPublic()) {
        SecretKey.generate().use { signer ->
            signer.publicKey().use { verifier ->
                val token = signer.signClaims(claims)
                println("cb2.public token: ${token.length} chars")
                println("verified:         " + verifier.verifyClaims(token) { issuer("https://issuer.example"); audience("api") })
            }
        }
    }
}
