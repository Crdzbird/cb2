package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Rules
import org.junit.jupiter.api.Assertions.assertEquals
import java.time.Instant

internal val EXP: Instant = Instant.parse("2099-01-01T00:00:00Z")
internal const val NOW = 1700000000L
internal const val TARGET = "https://api.example/v1/me"

internal val CLAIMS: Map<String, Any?> = linkedMapOf(
    "iss" to "https://issuer.example",
    "sub" to "user-1",
    "aud" to "api",
    "exp" to EXP,
    "jti" to "id-1",
    "role" to "admin",
)

internal fun base(): Rules = rules {
    issuer("https://issuer.example")
    audience("api")
    now(NOW)
}

internal fun expect(verdict: String, what: String, block: () -> Unit) {
    assertEquals(verdict, verdictOf(block), what)
}
