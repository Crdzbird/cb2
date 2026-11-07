package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Cb2Exception

/** The verdict name of this refusal, such as `"replayed"`. */
public val Cb2Exception.verdict: String
    get() = name()

/** Runs [block] and returns `"ok"`, or the verdict name of the [Cb2Exception] it threw. */
public inline fun verdictOf(block: () -> Unit): String =
    try {
        block()
        "ok"
    } catch (e: Cb2Exception) {
        e.verdict
    }

/** Runs [block] and returns its result, or null when the library refused with a [Cb2Exception]. */
public inline fun <T> cb2OrNull(block: () -> T): T? =
    try {
        block()
    } catch (e: Cb2Exception) {
        null
    }
