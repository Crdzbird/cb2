package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.Token
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class LocalKtTest {
    @Test
    fun rawTokens() {
        LocalKey.generate().use { k ->
            val paserk = k.toPaserk()
            assertTrue(paserk.startsWith("kcb2.local.") && paserk.length == 54, "local paserk shape")
            LocalKey.fromPaserk(paserk).use { same ->
                assertEquals(k.paserkId(), same.paserkId(), "paserk round trip")
                val footer = "{\"kid\":\"x\"}".toByteArray()
                val token = k.seal("hello".toByteArray(), footer)
                assertArrayEquals("hello".toByteArray(), same.open(token, footer), "local round trip")
                expect("invalid", "open without the footer") { same.open(token) }
            }
        }
    }

    @Test
    fun claimsTokens() {
        LocalKey.generate().use { k ->
            val ct = k.sealClaims(CLAIMS)
            val opened = k.openClaims(ct, base())
            assertTrue("\"role\":\"admin\"" in opened, "custom claim comes back")
            assertTrue("\"exp\":\"2099-01-01T00:00:00+00:00\"" in opened, "exp comes back")
            assertEquals(k.paserkId(), Token.peekKeyId(ct), "peeked key id")
            expect("rules_incomplete", "empty rules") { k.openClaims(ct) {} }
            expect("audience_mismatch", "other audience") {
                k.openClaims(ct) {
                    issuer("https://issuer.example")
                    audience("other")
                    now(NOW)
                }
            }
            expect("expired", "late clock") { k.openClaims(ct, base().now(4102444801L)) }
            expect("lifetime_exceeded", "max lifetime") { k.openClaims(ct, base().maxLifetime(60)) }
            expect("argument", "claims with a zero-width space") { k.sealClaims(claims("sub" to "a\u200bb", "exp" to EXP)) }
            assertNull(cb2OrNull { k.openClaims(ct, base().audience("other")) }, "cb2OrNull on a refusal")
        }
    }

    @Test
    fun replayChecks() {
        LocalKey.generate().use { k ->
            val ct = k.sealClaims(CLAIMS)
            val seen = mutableSetOf<String>()
            k.openClaims(ct, base().onReplay { seen.add(it) })
            expect("replayed", "replayed via the lambda") { k.openClaims(ct, base().onReplay { seen.add(it) }) }
            val remember = rememberingCheck()
            k.openClaims(ct, base().replay(remember))
            expect("replayed", "replayed via rememberingCheck") { k.openClaims(ct, base().replay(remember)) }
            expect("replayed", "replayed via seen_jti") { k.openClaims(ct, base().seenJti("id-1")) }
            expect("replayed", "a throwing lambda refuses") { k.openClaims(ct, base().onReplay { error("store down") }) }
        }
    }

    @Test
    fun wrappingAndKeyIds() {
        LocalKey.generate().use { k ->
            LocalKey.generate().use { wrapping ->
                val wrapped = k.wrapWith(wrapping)
                assertTrue(wrapped.startsWith("kcb2.local-wrap.") && wrapped.length == 144, "wrapped shape")
                wrapped.unwrapWith(wrapping).use { back -> assertEquals(k.paserkId(), back.paserkId(), "unwrapped key is the same key") }
                expect("invalid", "unwrap with the wrong key") { wrapped.unwrapWith(k) }
            }
            k.setKeyId("rotation-1")
            assertEquals("rotation-1", k.keyId(), "key id set")
            expect("argument", "key id with a zero-width space") { k.setKeyId("a\u200b") }
            k.clearKeyId()
            assertNull(k.keyId(), "key id cleared")
        }
        expect("argument", "weak key bytes") { LocalKey.fromBytes(ByteArray(32) { 7 }) }
    }
}
