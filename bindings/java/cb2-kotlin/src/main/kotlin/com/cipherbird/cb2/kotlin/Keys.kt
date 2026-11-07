package com.cipherbird.cb2.kotlin

import com.cipherbird.cb2.Holder
import com.cipherbird.cb2.KeyWrap
import com.cipherbird.cb2.Local
import com.cipherbird.cb2.LocalKey
import com.cipherbird.cb2.Public
import com.cipherbird.cb2.PublicKey
import com.cipherbird.cb2.RecipientKey
import com.cipherbird.cb2.RecipientPublicKey
import com.cipherbird.cb2.Rules
import com.cipherbird.cb2.Seal
import com.cipherbird.cb2.SecretKey
import com.cipherbird.cb2.Token

/** Seals a raw [message] under this key as a cb2.local token. */
public fun LocalKey.seal(message: ByteArray, footer: ByteArray? = null, implicit: ByteArray? = null): String =
    Local.seal(this, message, footer, implicit)

/** Opens a raw cb2.local [token] under this key and returns its message. */
public fun LocalKey.open(
    token: String,
    footer: ByteArray? = null,
    implicit: ByteArray? = null,
    maxTokenBytes: Long = 0,
): ByteArray = Local.open(this, token, footer, implicit, maxTokenBytes)

/** Seals [claims] given as a map under this key. */
public fun LocalKey.sealClaims(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Token.seal(this, claims.toClaimsJson(), implicit)

/** Seals claims given as JSON text under this key. */
public fun LocalKey.sealClaims(claimsJson: String, implicit: ByteArray? = null): String =
    Token.seal(this, claimsJson, implicit)

/** Opens a claims [token] under this key against [rules] and returns the claims JSON. */
public fun LocalKey.openClaims(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Token.open(this, token, rules, implicit)

/** Opens a claims [token] under this key against the rules [block] builds. */
public inline fun LocalKey.openClaims(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Token.open(this, token, rules(block), implicit)

/** Signs a raw [message] with this pair as a cb2.public token. */
public fun SecretKey.sign(message: ByteArray, footer: ByteArray? = null, implicit: ByteArray? = null): String =
    Public.sign(this, message, footer, implicit)

/** Verifies a raw cb2.public [token] with this key and returns its message. */
public fun PublicKey.verify(
    token: String,
    footer: ByteArray? = null,
    implicit: ByteArray? = null,
    maxTokenBytes: Long = 0,
): ByteArray = Public.verify(this, token, footer, implicit, maxTokenBytes)

/** Signs [claims] given as a map with this pair. */
public fun SecretKey.signClaims(claims: Map<String, Any?>, implicit: ByteArray? = null): String =
    Token.sign(this, claims.toClaimsJson(), implicit)

/** Signs claims given as JSON text with this pair. */
public fun SecretKey.signClaims(claimsJson: String, implicit: ByteArray? = null): String =
    Token.sign(this, claimsJson, implicit)

/** Verifies a claims [token] with this key against [rules] and returns the claims JSON. */
public fun PublicKey.verifyClaims(token: String, rules: Rules, implicit: ByteArray? = null): String =
    Token.verify(this, token, rules, implicit)

/** Verifies a claims [token] with this key against the rules [block] builds. */
public inline fun PublicKey.verifyClaims(token: String, implicit: ByteArray? = null, block: Rules.() -> Unit): String =
    Token.verify(this, token, rules(block), implicit)

/** Proves possession of this client pair for one request and one [accessToken] (public mode). */
public fun SecretKey.prove(
    htm: String,
    htu: String,
    accessToken: String,
    jti: String,
    now: Long,
    lifetime: Long = 60,
    nonce: String? = null,
): String = Holder.prove(this, htm, htu, nonce, accessToken, jti, now, lifetime)

/** Proves possession of this local proof key, the one in cnf of the cb2.local [accessToken], for one request. */
public fun LocalKey.prove(
    htm: String,
    htu: String,
    accessToken: String,
    jti: String,
    now: Long,
    lifetime: Long = 60,
    nonce: String? = null,
): String = Holder.proveLocal(this, htm, htu, nonce, accessToken, jti, now, lifetime)

/** Wraps this key under [wrapping] as kcb2.local-wrap text. */
public fun LocalKey.wrapWith(wrapping: LocalKey): String = KeyWrap.wrap(wrapping, this)

/** Unwraps this kcb2.local-wrap text under [wrapping] into a key the caller closes. */
public fun String.unwrapWith(wrapping: LocalKey): LocalKey = KeyWrap.unwrap(this, wrapping)

/** Seals this key to the recipient [to] as kcb2.seal text. */
public fun LocalKey.sealTo(to: RecipientPublicKey): String = Seal.seal(to, this)

/** Unseals this kcb2.seal text with the recipient pair [by] into a key the caller closes. */
public fun String.unsealBy(by: RecipientKey): LocalKey = Seal.unseal(this, by)
