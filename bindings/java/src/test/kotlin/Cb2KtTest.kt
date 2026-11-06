import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.Cb2Exception
import com.cipherbird.cb2.Holder
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.RecipientKey
import com.cipherbird.cb2.Rules
import com.cipherbird.cb2.SecretKey
import com.cipherbird.cb2.Token
import com.cipherbird.cb2.claims
import com.cipherbird.cb2.open
import com.cipherbird.cb2.openClaims
import com.cipherbird.cb2.onProofReplay
import com.cipherbird.cb2.onReplay
import com.cipherbird.cb2.prove
import com.cipherbird.cb2.rememberingCheck
import com.cipherbird.cb2.rules
import com.cipherbird.cb2.seal
import com.cipherbird.cb2.sealClaims
import com.cipherbird.cb2.sealTo
import com.cipherbird.cb2.signClaims
import com.cipherbird.cb2.toClaimsJson
import com.cipherbird.cb2.unsealBy
import com.cipherbird.cb2.unwrapWith
import com.cipherbird.cb2.verdictOf
import com.cipherbird.cb2.verifyClaims
import com.cipherbird.cb2.wrapWith
import java.time.Instant

/**
 * The Kotlin layer exercised over the same ground as test_c.c, through
 * the DSL, the claims map helper and the extension functions. Throws on
 * the first failed check.
 */
object Cb2KtTest {
    private val exp: Instant = Instant.parse("2099-01-01T00:00:00Z")

    private val claimsMap: Map<String, Any?> = linkedMapOf(
        "iss" to "https://issuer.example",
        "sub" to "user-1",
        "aud" to "api",
        "exp" to exp,
        "jti" to "id-1",
        "role" to "admin",
    )

    private fun check(condition: Boolean, what: String) {
        if (!condition) throw AssertionError("FAIL $what")
    }

    private fun expect(verdict: String, what: String, block: () -> Unit) {
        val got = verdictOf(block)
        check(got == verdict, "$what: expected $verdict, got $got")
    }

    private fun base(): Rules = rules {
        issuer("https://issuer.example")
        audience("api")
        now(1700000000L)
    }

    private fun testJson() {
        val json = claims("a" to "q\"\\\n", "n" to 1, "b" to true, "z" to null, "l" to listOf(1, "x"), "m" to mapOf("k" to 2.5))
        check(json == "{\"a\":\"q\\\"\\\\\\n\",\"n\":1,\"b\":true,\"z\":null,\"l\":[1,\"x\"],\"m\":{\"k\":2.5}}", "claims json: $json")
        check(mapOf("exp" to exp).toClaimsJson() == "{\"exp\":\"2099-01-01T00:00:00+00:00\"}", "instant as rfc 3339")
        val refused = try {
            mapOf("o" to Any()).toClaimsJson()
            false
        } catch (e: IllegalArgumentException) {
            true
        }
        check(refused, "an unsupported value is refused")
    }

    private fun testLocal() {
        LocalKey.generate().use { k ->
            val paserk = k.toPaserk()
            check(paserk.startsWith("kcb2.local.") && paserk.length == 54, "local paserk shape")
            val id = k.paserkId()
            LocalKey.fromPaserk(paserk).use { same ->
                check(same.paserkId() == id, "paserk round trip")
                val footer = "{\"kid\":\"x\"}".toByteArray()
                val token = k.seal("hello".toByteArray(), footer)
                check(same.open(token, footer).contentEquals("hello".toByteArray()), "local round trip")
                expect("invalid", "open without the footer") { same.open(token) }
            }

            val ct = k.sealClaims(claimsMap)
            val opened = k.openClaims(ct, base())
            check("\"role\":\"admin\"" in opened && "\"exp\":\"2099-01-01T00:00:00+00:00\"" in opened, "claims come back")
            check(Token.peekKeyId(ct) == id, "peeked key id")
            expect("rules_incomplete", "empty rules") { k.openClaims(ct) {} }
            expect("audience_mismatch", "other audience") { k.openClaims(ct) { issuer("https://issuer.example"); audience("other"); now(1700000000L) } }
            expect("expired", "late clock") { k.openClaims(ct, base().now(4102444801L)) }

            val seen = mutableSetOf<String>()
            k.openClaims(ct, base().onReplay { seen.add(it) })
            expect("replayed", "replayed via the lambda") { k.openClaims(ct, base().onReplay { seen.add(it) }) }
            val remember = rememberingCheck()
            k.openClaims(ct, base().replay(remember))
            expect("replayed", "replayed via rememberingCheck") { k.openClaims(ct, base().replay(remember)) }
            expect("replayed", "replayed via seen_jti") { k.openClaims(ct, base().seenJti("id-1")) }
            expect("replayed", "a throwing lambda refuses") { k.openClaims(ct, base().onReplay { error("store down") }) }
            expect("lifetime_exceeded", "max lifetime") { k.openClaims(ct, base().maxLifetime(60)) }
            expect("argument", "claims with a zero-width space") { k.sealClaims(claims("sub" to "a\u200bb", "exp" to exp)) }

            LocalKey.generate().use { wrapping ->
                val wrapped = k.wrapWith(wrapping)
                check(wrapped.startsWith("kcb2.local-wrap.") && wrapped.length == 144, "wrapped shape")
                wrapped.unwrapWith(wrapping).use { back -> check(back.paserkId() == id, "unwrapped key is the same key") }
                expect("invalid", "unwrap with the wrong key") { wrapped.unwrapWith(k) }
            }

            k.setKeyId("rotation-1")
            check(k.keyId() == "rotation-1", "key id set")
            expect("argument", "key id with a zero-width space") { k.setKeyId("a\u200b") }
            k.clearKeyId()
            check(k.keyId() == null, "key id cleared")
        }
        expect("argument", "weak key bytes") { LocalKey.fromBytes(ByteArray(32) { 7 }) }
    }

    private fun testPublic() {
        if (!Cb2.hasPublic()) {
            println("cb2.public unavailable in this build; skipping")
            return
        }
        SecretKey.generate().use { sk ->
            sk.publicKey().use { pk ->
                SecretKey.generate().use { stranger ->
                    stranger.publicKey().use { spk ->
                        LocalKey.generate().use { k -> testBound(sk, pk, stranger, spk, k) }
                    }
                }
            }
        }
    }

    private fun testBound(sk: SecretKey, pk: com.cipherbird.cb2.PublicKey, stranger: SecretKey, spk: com.cipherbird.cb2.PublicKey, k: LocalKey) {
        check(pk.toPaserk().length == 2658, "public paserk length")
        val token = sk.signClaims(claimsMap)
        check("\"sub\":\"user-1\"" in pk.verifyClaims(token, base()), "verified claims")
        expect("invalid", "verify with a stranger's key") { spk.verifyClaims(token) { issuer("https://issuer.example"); audience("api"); now(1700000000L) } }

        val access = k.sealClaims(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to exp, "cnf" to spk.toPaserk()))
        expect("missing_proof", "bound token without a proof") { k.openClaims(access, base()) }
        val proof = stranger.prove("GET", "https://api.example/v1/me", access, "p-1", 1700000000L)
        check(proof.startsWith("cb2.holder-public."), "proof prefix")
        expect("rules_incomplete", "proof without a proof replay check") {
            k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1"))
        }
        val proofs = mutableSetOf<String>()
        k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1").onProofReplay { proofs.add(it) })
        expect("proof_replayed", "proof id already seen by the lambda") {
            k.openClaims(access, base().proof(proof).request("GET", "https://api.example/v1/me").onProofReplay { proofs.add(it) })
        }
        expect("proof_mismatch", "proof for another request") {
            k.openClaims(access, base().proof(proof).request("POST", "https://api.example/v1/me").proofSeenJti())
        }
        expect("proof_replayed", "proof id in proof_seen_jti") {
            k.openClaims(access, base().proof(proof).request("GET", "https://api.example/v1/me").proofSeenJti("p-1"))
        }
        expect("proof_expired", "proof too old") {
            k.openClaims(access, base().now(1700000100L).proof(proof).request("GET", "https://api.example/v1/me").proofSeenJti())
        }
        k.openClaims(access, base().ignoreCnf(true))
        check(Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c") == "https://api.example/a", "normalised target")
        expect("argument", "normalise a non-target") { Holder.normalizeTarget("nope") }
        val e = try {
            k.openClaims(access, base())
            null
        } catch (e: Cb2Exception) {
            e
        }
        check(e != null && e.code() == 19 && e.message == "cb2: missing_proof (19)", "exception carries code and name")
    }

    private fun testHolderLocal() {
        LocalKey.generate().use { k ->
            LocalKey.generate().use { issued ->
                val cnf = issued.toPaserk()
                val access = k.sealClaims(claims("iss" to "https://issuer.example", "aud" to "api", "exp" to exp, "cnf" to cnf))
                expect("missing_proof", "local-bound token without a proof") { k.openClaims(access, base()) }
                LocalKey.fromPaserk(cnf).use { client ->
                    val proof = client.prove("GET", "https://api.example/v1/me", access, "p-1", 1700000000L)
                    check(proof.startsWith("cb2.holder-local."), "local proof prefix")
                    val proofs = mutableSetOf<String>()
                    k.openClaims(access, base().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1").onProofReplay { proofs.add(it) })
                    expect("proof_replayed", "local proof id already seen by the lambda") {
                        k.openClaims(access, base().proof(proof).request("GET", "https://api.example/v1/me").onProofReplay { proofs.add(it) })
                    }
                    expect("proof_mismatch", "local proof for another request") {
                        k.openClaims(access, base().proof(proof).request("POST", "https://api.example/v1/me").proofSeenJti())
                    }
                }
                LocalKey.generate().use { stranger ->
                    val forged = stranger.prove("GET", "https://api.example/v1/me", access, "p-2", 1700000000L)
                    expect("proof_invalid", "local proof under another key") {
                        k.openClaims(access, base().proof(forged).request("GET", "https://api.example/v1/me").proofSeenJti())
                    }
                }
            }
        }
    }

    private fun testSeal() {
        if (!Cb2.hasSeal()) {
            println("kcb2.seal unavailable in this build; skipping")
            return
        }
        RecipientKey.generate().use { r ->
            r.publicKey().use { rp ->
                LocalKey.generate().use { k ->
                    check(rp.toPaserk().length == 1637, "recipient paserk length")
                    val sealed = k.sealTo(rp)
                    check(sealed.length == 1632, "sealed length")
                    RecipientKey.fromPaserk(r.toPaserk()).use { r2 ->
                        sealed.unsealBy(r2).use { back -> check(back.paserkId() == k.paserkId(), "unsealed key is the same key") }
                        check(r2.paserkId() == rp.paserkId(), "recipient ids")
                    }
                    RecipientKey.generate().use { other -> expect("invalid", "unseal by another recipient") { sealed.unsealBy(other) } }
                }
            }
        }
    }

    @JvmStatic
    fun main(args: Array<String>) {
        println("cb2 ${Cb2.version()} from Kotlin, public ${Cb2.hasPublic()}, seal ${Cb2.hasSeal()}")
        testJson()
        testLocal()
        testHolderLocal()
        testPublic()
        testSeal()
        println("Cb2KtTest: all checks passed")
    }
}
