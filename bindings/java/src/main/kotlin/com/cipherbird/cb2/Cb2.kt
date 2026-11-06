@file:JvmName("Cb2Kt")

package com.cipherbird.cb2

import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Idiomatic Kotlin over the Java classes: a rules DSL with lambdas for
 * the replay checks, a claims map to JSON helper, extension functions on
 * the keys, and verdict helpers. The keys implement AutoCloseable, so
 * the standard use {} releases them.
 */

private val RFC3339: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx")

/** Builds rules with a lambda: rules { issuer("..."); audience("...") }. */
inline fun rules(block: Rules.() -> Unit): Rules = Rules().apply(block)

/** Runs check on the token id; a refused id is the replayed verdict. */
fun Rules.onReplay(check: (String) -> Boolean): Rules = replay(ReplayCheck { check(it) })

/** Runs check on the proof id; a refused id is the proof_replayed verdict. */
fun Rules.onProofReplay(check: (String) -> Boolean): Rules = proofReplay(ReplayCheck { check(it) })

/** A replay check backed by a mutable set that remembers every id it accepts. */
fun rememberingCheck(seen: MutableSet<String> = mutableSetOf()): ReplayCheck = ReplayCheck { seen.add(it) }

/**
 * The claims JSON for a map. Strings, booleans, numbers, null, nested
 * maps and lists are written as JSON; Instant and OffsetDateTime become
 * RFC 3339 strings. Any other value is refused with IllegalArgumentException.
 */
fun Map<String, Any?>.toClaimsJson(): String = buildString { appendJson(this@toClaimsJson) }

/** The claims JSON for pairs: claims("iss" to "...", "exp" to Instant). */
fun claims(vararg pairs: Pair<String, Any?>): String = linkedMapOf(*pairs).toClaimsJson()

private fun StringBuilder.appendJson(value: Any?) {
    when (value) {
        null -> append("null")
        is String -> Json.quoteTo(this, value)
        is Boolean -> append(value)
        is Int, is Long, is Short, is Byte -> append(value)
        is Double, is Float -> appendFinite(value.toDouble())
        is Number -> append(value.toString())
        is Instant -> Json.quoteTo(this, RFC3339.format(value.atOffset(ZoneOffset.UTC)))
        is OffsetDateTime -> Json.quoteTo(this, RFC3339.format(value))
        is Map<*, *> -> appendObject(value)
        is Iterable<*> -> appendArray(value)
        is Array<*> -> appendArray(value.asIterable())
        else -> throw IllegalArgumentException("claims cannot hold a ${value::class.java.name}")
    }
}

private fun StringBuilder.appendFinite(value: Double) {
    require(value.isFinite()) { "claims cannot hold $value" }
    append(value)
}

private fun StringBuilder.appendObject(map: Map<*, *>) {
    append('{')
    var first = true
    for ((key, item) in map) {
        if (!first) append(',')
        first = false
        Json.quoteTo(this, key.toString())
        append(':')
        appendJson(item)
    }
    append('}')
}

private fun StringBuilder.appendArray(items: Iterable<*>) {
    append('[')
    var first = true
    for (item in items) {
        if (!first) append(',')
        first = false
        appendJson(item)
    }
    append(']')
}

/** Seals a raw message under this key. */
fun LocalKey.seal(message: ByteArray, footer: ByteArray? = null, implicit: ByteArray? = null): String =
    Local.seal(this, message, footer, implicit)

/** Opens a raw token under this key. */
fun LocalKey.open(token: String, footer: ByteArray? = null, implicit: ByteArray? = null, maxTokenBytes: Long = 0): ByteArray =
    Local.open(this, token, footer, implicit, maxTokenBytes)

/** Seals claims given as a map under this key. */
fun LocalKey.sealClaims(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Token.seal(this, claims.toClaimsJson(), implicit)

/** Seals claims given as JSON text under this key. */
fun LocalKey.sealClaims(claimsJson: String, implicit: ByteArray? = null): String =
    Token.seal(this, claimsJson, implicit)

/** Opens a claims token under this key against rules and returns the claims JSON. */
fun LocalKey.openClaims(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Token.open(this, token, rules, implicit)

/** Opens a claims token under this key against rules built by block. */
inline fun LocalKey.openClaims(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Token.open(this, token, rules(block), implicit)

/** Signs a raw message with this key. */
fun SecretKey.sign(message: ByteArray, footer: ByteArray? = null, implicit: ByteArray? = null): String =
    Public.sign(this, message, footer, implicit)

/** Verifies a raw token with this key. */
fun PublicKey.verify(token: String, footer: ByteArray? = null, implicit: ByteArray? = null, maxTokenBytes: Long = 0): ByteArray =
    Public.verify(this, token, footer, implicit, maxTokenBytes)

/** Signs claims given as a map with this key. */
fun SecretKey.signClaims(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Token.sign(this, claims.toClaimsJson(), implicit)

/** Signs claims given as JSON text with this key. */
fun SecretKey.signClaims(claimsJson: String, implicit: ByteArray? = null): String =
    Token.sign(this, claimsJson, implicit)

/** Verifies a claims token with this key against rules and returns the claims JSON. */
fun PublicKey.verifyClaims(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Token.verify(this, token, rules, implicit)

/** Verifies a claims token with this key against rules built by block. */
inline fun PublicKey.verifyClaims(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Token.verify(this, token, rules(block), implicit)

/** Proves possession of this client pair for one request and one access token. */
fun SecretKey.prove(
    htm: String,
    htu: String,
    accessToken: String,
    jti: String,
    now: Long,
    lifetime: Long = 60,
    nonce: String? = null,
): String = Holder.prove(this, htm, htu, nonce, accessToken, jti, now, lifetime)

/** Proves possession of this local proof key, the one in cnf of the cb2.local accessToken, for one request. */
fun LocalKey.prove(
    htm: String,
    htu: String,
    accessToken: String,
    jti: String,
    now: Long,
    lifetime: Long = 60,
    nonce: String? = null,
): String = Holder.proveLocal(this, htm, htu, nonce, accessToken, jti, now, lifetime)

/** Wraps this key under wrapping. */
fun LocalKey.wrapWith(wrapping: LocalKey): String = KeyWrap.wrap(wrapping, this)

/** Unwraps this kcb2.local-wrap text under wrapping. */
fun String.unwrapWith(wrapping: LocalKey): LocalKey = KeyWrap.unwrap(this, wrapping)

/** Seals this key to a recipient. */
fun LocalKey.sealTo(to: RecipientPublicKey): String = Seal.seal(to, this)

/** Unseals this kcb2.seal text with the recipient pair by. */
fun String.unsealBy(by: RecipientKey): LocalKey = Seal.unseal(this, by)

/** The verdict name of a refusal. */
val Cb2Exception.verdict: String
    get() = name()

/** Runs block and returns "ok" or the verdict name of the Cb2Exception it threw. */
inline fun verdictOf(block: () -> Unit): String =
    try {
        block()
        "ok"
    } catch (e: Cb2Exception) {
        e.verdict
    }

/** Runs block and returns its result, or null when the library refused with a Cb2Exception. */
inline fun <T> cb2OrNull(block: () -> T): T? =
    try {
        block()
    } catch (e: Cb2Exception) {
        null
    }
