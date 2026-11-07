package com.cipherbird.cb2.kotlin

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.time.OffsetDateTime
import java.time.ZoneOffset

class ClaimsJsonTest {
    @Test
    fun valuesAreWrittenAsJson() {
        val json = claims(
            "a" to "q\"\\\n",
            "n" to 1,
            "b" to true,
            "z" to null,
            "l" to listOf(1, "x"),
            "m" to mapOf("k" to 2.5),
            "r" to arrayOf("y"),
        )
        assertEquals(
            "{\"a\":\"q\\\"\\\\\\n\",\"n\":1,\"b\":true,\"z\":null,\"l\":[1,\"x\"],\"m\":{\"k\":2.5},\"r\":[\"y\"]}",
            json,
            "claims json",
        )
    }

    @Test
    fun timesAreRfc3339() {
        assertEquals("{\"exp\":\"2099-01-01T00:00:00+00:00\"}", mapOf("exp" to EXP).toClaimsJson(), "instant as rfc 3339")
        val offset = OffsetDateTime.of(2099, 1, 1, 2, 0, 0, 0, ZoneOffset.ofHours(2))
        assertEquals("{\"t\":\"2099-01-01T02:00:00+02:00\"}", mapOf("t" to offset).toClaimsJson(), "offset date time")
    }

    @Test
    fun unsupportedValuesAreRefused() {
        assertThrows(IllegalArgumentException::class.java, { mapOf("o" to Any()).toClaimsJson() }, "an unsupported value")
        assertThrows(IllegalArgumentException::class.java, { mapOf("d" to Double.NaN).toClaimsJson() }, "a NaN")
    }

    @Test
    fun rulesDsl() {
        val check = rememberingCheck()
        val rules = rules {
            issuer("i")
            audience("a")
            replay(check)
        }
        assertEquals("{\"issuer\":\"i\",\"audience\":\"a\",\"replay\":true}", rules.toJson(), "rules json")
        assertSame(check, rules.replayCheck(), "the check is kept beside the json")
    }
}
