package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Json
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

private val RFC3339: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx")

/**
 * The claims JSON for this map. Strings, booleans, numbers, null, nested
 * maps, lists and arrays are written as JSON; [Instant] and
 * [OffsetDateTime] become RFC 3339 strings at whole seconds.
 *
 * @throws IllegalArgumentException for any other value, or a number that
 *     is not finite
 */
public fun Map<String, Any?>.toClaimsJson(): String = buildString { appendJson(this@toClaimsJson) }

/** The claims JSON for [pairs], in order: `claims("iss" to "...", "exp" to Instant.now())`. */
public fun claims(vararg pairs: Pair<String, Any?>): String = linkedMapOf(*pairs).toClaimsJson()

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
