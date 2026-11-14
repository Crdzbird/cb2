package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Compact
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.PublicKey
import com.cipherbird.cb2.Rules
import com.cipherbird.cb2.SecretKey

/** Seals [claims] given as a map under this key as a compact local token. */
public fun LocalKey.sealCompact(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Compact.seal(this, claims.toClaimsJson(), implicit)

/** Seals claims given as JSON text under this key as a compact local token. */
public fun LocalKey.sealCompact(claimsJson: String, implicit: ByteArray? = null): String =
    Compact.seal(this, claimsJson, implicit)

/** Opens a compact local [token] under this key against [rules] and returns the claims JSON. */
public fun LocalKey.openCompact(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Compact.open(this, token, rules, implicit)

/** Opens a compact local [token] under this key against the rules [block] builds. */
public inline fun LocalKey.openCompact(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Compact.open(this, token, rules(block), implicit)

/** Signs [claims] given as a map with this pair as a compact public token. */
public fun SecretKey.signCompact(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Compact.sign(this, claims.toClaimsJson(), implicit)

/** Signs claims given as JSON text with this pair as a compact public token. */
public fun SecretKey.signCompact(claimsJson: String, implicit: ByteArray? = null): String =
    Compact.sign(this, claimsJson, implicit)

/** Verifies a compact public [token] with this key against [rules] and returns the claims JSON. */
public fun PublicKey.verifyCompact(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Compact.verify(this, token, rules, implicit)

/** Verifies a compact public [token] with this key against the rules [block] builds. */
public inline fun PublicKey.verifyCompact(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Compact.verify(this, token, rules(block), implicit)

/** The key digest the footer of this compact token carries, unverified, or null when it carries none. */
public fun String.peekCompactKeyDigest(): ByteArray? = Compact.peekKeyDigest(this)

/** The digest a compact token issued under this key carries, or null when the key has no id. */
public val LocalKey.compactKeyDigest: ByteArray?
    get() = keyId()?.let(Compact::keyDigest)

/** The digest a compact token signed by this pair carries, or null when the pair has no id. */
public val SecretKey.compactKeyDigest: ByteArray?
    get() = keyId()?.let(Compact::keyDigest)

/** The digest a compact token carries when this key's pair signed it, or null when the key has no id. */
public val PublicKey.compactKeyDigest: ByteArray?
    get() = keyId()?.let(Compact::keyDigest)
