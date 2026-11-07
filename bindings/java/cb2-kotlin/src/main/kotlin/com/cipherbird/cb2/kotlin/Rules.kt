package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.ReplayCheck
import com.cipherbird.cb2.Rules
import java.util.concurrent.ConcurrentHashMap

/** Builds rules with a lambda: `rules { issuer("..."); audience("...") }`. */
public inline fun rules(block: Rules.() -> Unit): Rules = Rules().apply(block)

/** Runs [check] on the token id; an id it refuses is the replayed verdict. */
public fun Rules.onReplay(check: (String) -> Boolean): Rules = replay(ReplayCheck { check(it) })

/** Runs [check] on the proof id; an id it refuses is the proof_replayed verdict. */
public fun Rules.onProofReplay(check: (String) -> Boolean): Rules = proofReplay(ReplayCheck { check(it) })

/**
 * A replay check backed by [seen], which remembers every id it accepts
 * and refuses an id it has seen. The default set is safe to share between
 * threads.
 */
public fun rememberingCheck(seen: MutableSet<String> = ConcurrentHashMap.newKeySet()): ReplayCheck =
    ReplayCheck { seen.add(it) }
