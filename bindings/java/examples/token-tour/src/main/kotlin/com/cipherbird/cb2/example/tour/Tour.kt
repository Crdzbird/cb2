package com.cipherbird.cb2.example.tour

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.RecipientKey
import com.cipherbird.cb2.SecretKey
import com.cipherbird.cb2.kotlin.claims
import com.cipherbird.cb2.kotlin.openClaims
import com.cipherbird.cb2.kotlin.prove
import com.cipherbird.cb2.kotlin.rememberingCheck
import com.cipherbird.cb2.kotlin.sealClaims
import com.cipherbird.cb2.kotlin.sealTo
import com.cipherbird.cb2.kotlin.signClaims
import com.cipherbird.cb2.kotlin.unsealBy
import com.cipherbird.cb2.kotlin.verdictOf
import com.cipherbird.cb2.kotlin.verifyClaims
import java.time.Instant

private const val ISSUER = "https://issuer.example"
private const val TARGET = "https://api.example/v1/me"

fun main() {
    println("cb2 ${Cb2.version()} from Kotlin, public ${Cb2.hasPublic()}, seal ${Cb2.hasSeal()}")
    LocalKey.generate().use { key ->
        local(key)
        if (Cb2.hasPublic()) signed()
        holder(key)
        if (Cb2.hasSeal()) sealing(key)
    }
}

private fun local(key: LocalKey) {
    section("cb2.local")
    val exp = Instant.now().plusSeconds(3600)
    val token = key.sealClaims(claims("iss" to ISSUER, "aud" to "api", "sub" to "user-1", "exp" to exp, "jti" to "id-1"))
    line("sealed", "${token.take(24)}... (${token.length} chars)")
    val seen = rememberingCheck()
    line("opened", key.openClaims(token) { issuer(ISSUER); audience("api"); replay(seen) })
    line("refused", verdictOf { key.openClaims(token) { issuer(ISSUER); audience("api"); replay(seen) } } + ", the same jti again")
    line("refused", verdictOf { key.openClaims(token) { issuer(ISSUER); audience("billing") } } + ", a token for another audience")
    line("refused", verdictOf { key.openClaims(token) { issuer(ISSUER); audience("api"); now(exp.epochSecond + 1) } } + ", one second after exp")
    val tampered = token.dropLast(1) + if (token.last() == 'A') 'B' else 'A'
    line("refused", verdictOf { key.openClaims(tampered) { issuer(ISSUER); audience("api") } } + ", one character changed")
}

private fun holder(key: LocalKey) {
    section("holder proof, local mode")
    LocalKey.generate().use { proofKey ->
        val access = key.sealClaims(claims("iss" to ISSUER, "aud" to "api", "exp" to Instant.now().plusSeconds(600), "cnf" to proofKey.toPaserk()))
        line("issued", "a cb2.local token with a kcb2.local proof key in cnf")
        val now = Instant.now().epochSecond
        val proof = proofKey.prove("GET", TARGET, access, "proof-1", now)
        val proofs = rememberingCheck()
        val server = { method: String, presented: String? ->
            verdictOf {
                key.openClaims(access) {
                    issuer(ISSUER)
                    audience("api")
                    if (presented != null) proof(presented)
                    request(method, TARGET)
                    proofReplay(proofs)
                }
            }
        }
        line("checked", server("GET", proof) + ", GET $TARGET with the proof")
        line("refused", server("GET", proof) + ", the same proof again")
        line("refused", server("POST", proofKey.prove("GET", TARGET, access, "proof-2", now)) + ", a GET proof on a POST")
        line("refused", server("GET", null) + ", no proof at all")
    }
}

private fun signed() {
    section("cb2.public")
    SecretKey.generate().use { issuer ->
        issuer.publicKey().use { verifier ->
            val token = issuer.signClaims(claims("iss" to ISSUER, "aud" to "api", "sub" to "user-2", "exp" to Instant.now().plusSeconds(600)))
            line("signed", "${token.take(24)}... (${token.length} chars)")
            line("verified", verifier.verifyClaims(token) { issuer(ISSUER); audience("api") })
            SecretKey.generate().use { other ->
                other.publicKey().use { stranger ->
                    line("refused", verdictOf { stranger.verifyClaims(token) { issuer(ISSUER); audience("api") } } + ", verified with another issuer's key")
                }
            }
        }
    }
}

private fun sealing(key: LocalKey) {
    section("kcb2.seal")
    RecipientKey.generate().use { recipient ->
        recipient.publicKey().use { to ->
            val sealed = key.sealTo(to)
            line("sealed", "the token key to a recipient (${sealed.length} chars)")
            sealed.unsealBy(recipient).use { back -> line("unsealed", "same key: ${back.paserkId() == key.paserkId()}") }
        }
    }
}

private fun section(name: String) = println("\n$name")

private fun line(what: String, detail: String) = println("  %-9s %s".format(what, detail))
