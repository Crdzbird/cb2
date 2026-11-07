package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.ClaimTable
import com.cipherbird.cb2.Compact
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.PublicKey
import com.cipherbird.cb2.Rules
import com.cipherbird.cb2.SecretKey

/** A claim table of [entries], in order, which the caller closes: `claimTable(issuer, "api", "billing")`. */
public fun claimTable(vararg entries: String): ClaimTable = ClaimTable.of(*entries)

/** A claim table of these entries, in order, which the caller closes. */
public fun Iterable<String>.toClaimTable(): ClaimTable = ClaimTable.of(toList())

/** Seals [claims] given as a map under this key and [table] as a compact local token. */
public fun LocalKey.sealCompact(table: ClaimTable, claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Compact.seal(this, table, claims.toClaimsJson(), implicit)

/** Seals claims given as JSON text under this key and [table] as a compact local token. */
public fun LocalKey.sealCompact(table: ClaimTable, claimsJson: String, implicit: ByteArray? = null): String =
    Compact.seal(this, table, claimsJson, implicit)

/** Opens a compact local [token] under this key and [table] against [rules] and returns the claims JSON. */
public fun LocalKey.openCompact(table: ClaimTable, token: String, rules: Rules, implicit: ByteArray? = null): String =
    Compact.open(this, table, token, rules, implicit)

/** Opens a compact local [token] under this key and [table] against the rules [block] builds. */
public inline fun LocalKey.openCompact(
    table: ClaimTable,
    token: String,
    implicit: ByteArray? = null,
    block: Rules.() -> Unit,
): String = Compact.open(this, table, token, rules(block), implicit)

/** Signs [claims] given as a map with this pair under [table] as a compact public token. */
public fun SecretKey.signCompact(table: ClaimTable, claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Compact.sign(this, table, claims.toClaimsJson(), implicit)

/** Signs claims given as JSON text with this pair under [table] as a compact public token. */
public fun SecretKey.signCompact(table: ClaimTable, claimsJson: String, implicit: ByteArray? = null): String =
    Compact.sign(this, table, claimsJson, implicit)

/** Verifies a compact public [token] with this key under [table] against [rules] and returns the claims JSON. */
public fun PublicKey.verifyCompact(table: ClaimTable, token: String, rules: Rules, implicit: ByteArray? = null): String =
    Compact.verify(this, table, token, rules, implicit)

/** Verifies a compact public [token] with this key under [table] against the rules [block] builds. */
public inline fun PublicKey.verifyCompact(
    table: ClaimTable,
    token: String,
    implicit: ByteArray? = null,
    block: Rules.() -> Unit,
): String = Compact.verify(this, table, token, rules(block), implicit)
