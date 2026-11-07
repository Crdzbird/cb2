package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.ClaimTable
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.SecretKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.util.HexFormat

private val ENTRIES = listOf("https://issuer.example", "api", "billing")

class ClaimTableKtTest {
    @Test
    fun refusedEntriesAndDigest() {
        expect("argument", "no entries") { claimTable() }
        expect("argument", "a repeated entry") { claimTable("a", "a") }
        expect("argument", "an empty entry") { listOf("a", "").toClaimTable() }
        expect("argument", "a control character") { claimTable("a\nb") }
        expect("argument", "257 entries") { (0..256).map { "e$it" }.toClaimTable() }
        ENTRIES.toClaimTable().use { t ->
            assertEquals("767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d", HexFormat.of().formatHex(t.digest()), "the known digest")
            assertEquals(ClaimTable.DIGEST_BYTES, t.digest().size, "digest size")
            assertEquals(ENTRIES, t.entries(), "the entries in order")
        }
    }

    @Test
    fun tabledTokens() {
        LocalKey.generate().use { k ->
            ENTRIES.toClaimTable().use { t ->
                claimTable("api", "https://issuer.example", "billing").use { other ->
                    val tabled = k.sealCompact(t, CLAIMS)
                    val plain = k.sealCompact(CLAIMS)
                    assertTrue(tabled.startsWith("cb3.local.") && tabled.length + 30 < plain.length, "a tabled token is shorter")
                    assertEquals(k.openCompact(plain, base()), k.openCompact(t, tabled, base()), "the same claims")
                    assertEquals(k.openCompact(t, tabled, base()), k.openCompact(t, k.sealCompact(t, CLAIMS.toClaimsJson()), base()), "map and JSON")
                    expect("invalid", "without the table") { k.openCompact(tabled, base()) }
                    expect("invalid", "a reordered table") { k.openCompact(other, tabled, base()) }
                    expect("invalid", "a tableless token under the table") { k.openCompact(t, plain, base()) }
                    expect("audience_mismatch", "another entry as audience") { k.openCompact(t, tabled, base().audience("billing")) }
                    expect("issuer_mismatch", "another issuer") {
                        k.openCompact(t, tabled) {
                            issuer("https://other.example")
                            audience("api")
                            now(NOW)
                        }
                    }
                    val any = k.openCompact(t, tabled) {
                        allowAnyIssuer(true)
                        allowAnyAudience(true)
                        now(NOW)
                    }
                    assertTrue("\"aud\":\"api\"" in any, "allow any")
                }
            }
        }
    }

    @Test
    fun reservedImplicit() {
        LocalKey.generate().use { k ->
            ENTRIES.toClaimTable().use { t ->
                val reserved = "kcb3.table.".toByteArray()
                expect("argument", "sealed without a table") { k.sealCompact(CLAIMS, reserved) }
                expect("argument", "opened without a table") { k.openCompact(k.sealCompact(CLAIMS), base(), reserved) }
                val tabled = k.sealCompact(t, CLAIMS, reserved)
                assertTrue("\"role\":\"admin\"" in k.openCompact(t, tabled, base(), reserved), "under a table")
            }
        }
    }

    @Test
    fun publicTokens() {
        assumeTrue(Cb2.hasPublic(), "cb2.public unavailable in this build")
        SecretKey.generate().use { sk ->
            sk.publicKey().use { pk ->
                ENTRIES.toClaimTable().use { t ->
                    val tabled = sk.signCompact(t, CLAIMS)
                    assertTrue(tabled.startsWith("cb3.public.") && tabled.length < sk.signCompact(CLAIMS).length, "a tabled token is shorter")
                    assertTrue("\"sub\":\"user-1\"" in pk.verifyCompact(t, tabled, base()), "verified under the table")
                    expect("invalid", "without the table") { pk.verifyCompact(tabled, base()) }
                    expect("audience_mismatch", "other audience") {
                        pk.verifyCompact(t, tabled) {
                            issuer("https://issuer.example")
                            audience("web")
                            now(NOW)
                        }
                    }
                }
            }
        }
    }
}
