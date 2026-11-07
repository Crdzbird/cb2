package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Cb2
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.RecipientKey
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test

class SealKtTest {
    @Test
    fun sealToARecipient() {
        assumeTrue(Cb2.hasSeal(), "kcb2.seal unavailable in this build")
        RecipientKey.generate().use { r ->
            r.publicKey().use { rp ->
                LocalKey.generate().use { k ->
                    assertEquals(1637, rp.toPaserk().length, "recipient paserk length")
                    val sealed = k.sealTo(rp)
                    assertEquals(1632, sealed.length, "sealed length")
                    RecipientKey.fromPaserk(r.toPaserk()).use { r2 ->
                        sealed.unsealBy(r2).use { back -> assertEquals(k.paserkId(), back.paserkId(), "unsealed key is the same key") }
                        assertEquals(rp.paserkId(), r2.paserkId(), "recipient ids")
                    }
                    RecipientKey.generate().use { other -> expect("invalid", "unseal by another recipient") { sealed.unsealBy(other) } }
                }
            }
        }
    }
}
