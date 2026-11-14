"""Raw, claims and compact claims tokens, holder proofs, key wrapping and sealing."""

from __future__ import annotations

import ctypes
import json
from collections.abc import Callable, Mapping
from ctypes import c_size_t, c_void_p
from typing import Any

from ._lib import BytesLike, as_bytes, lib, optional_text, take_bytes, take_text
from .claim_table import ClaimTable
from .errors import check
from .keys import LocalKey, PublicKey, RecipientKey, RecipientPublicKey, SecretKey, _Key
from .rules import RulesLike, prepare

Claims = dict[str, Any]
"""The claims of a token as a JSON object: iss, sub, aud, exp, jti, cnf and any custom claim."""

_Fn = Callable[..., int]


def _raw_make(fn: _Fn, key: _Key, msg: bytes, footer: bytes, implicit: bytes) -> str:
    out = c_void_p()
    length = c_size_t()
    check(
        fn(
            key.handle,
            msg,
            len(msg),
            footer,
            len(footer),
            implicit,
            len(implicit),
            ctypes.byref(out),
            ctypes.byref(length),
        )
    )
    return take_text(out.value, length.value)


def _raw_read(fn: _Fn, key: _Key, token: bytes, footer: bytes, implicit: bytes, max_token_bytes: int) -> bytes:
    out = c_void_p()
    length = c_size_t()
    check(
        fn(
            key.handle,
            token,
            len(token),
            footer,
            len(footer),
            implicit,
            len(implicit),
            max_token_bytes,
            ctypes.byref(out),
            ctypes.byref(length),
        )
    )
    return take_bytes(out.value, length.value)


def _claims_make(fn: _Fn, key: _Key, claims: Mapping[str, Any], implicit: bytes) -> str:
    text = json.dumps(dict(claims), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    out = c_void_p()
    length = c_size_t()
    check(fn(key.handle, text, len(text), implicit, len(implicit), ctypes.byref(out), ctypes.byref(length)))
    return take_text(out.value, length.value)


def _claims_read(fn: _Fn, key: _Key, token: bytes, rules: RulesLike, implicit: bytes) -> Claims:
    rules_json, replay, proof_replay = prepare(rules)
    out = c_void_p()
    length = c_size_t()
    code = fn(
        key.handle,
        token,
        len(token),
        rules_json,
        len(rules_json),
        implicit,
        len(implicit),
        replay,
        proof_replay,
        None,
        ctypes.byref(out),
        ctypes.byref(length),
    )
    del replay, proof_replay
    check(code)
    claims: Claims = json.loads(take_text(out.value, length.value))
    return claims


class Local:
    """cb2.local raw tokens: any bytes, encrypted and authenticated."""

    @staticmethod
    def seal(key: LocalKey, msg: bytes, footer: bytes = b"", implicit: bytes = b"") -> str:
        """Seals msg under key with an optional footer and implicit assertion."""
        return _raw_make(lib().cb2_local_seal, key, bytes(msg), bytes(footer), bytes(implicit))

    @staticmethod
    def open(
        token: BytesLike, key: LocalKey, footer: bytes = b"", implicit: bytes = b"", max_token_bytes: int = 0
    ) -> bytes:
        """Opens a token; the footer and implicit assertion must match."""
        raw = as_bytes(token, "token")
        return _raw_read(lib().cb2_local_open, key, raw, bytes(footer), bytes(implicit), max_token_bytes)


class Public:
    """cb2.public raw tokens: any bytes, signed."""

    @staticmethod
    def sign(key: SecretKey, msg: bytes, footer: bytes = b"", implicit: bytes = b"") -> str:
        """Signs msg with the pair, with an optional footer and implicit assertion."""
        return _raw_make(lib().cb2_public_sign, key, bytes(msg), bytes(footer), bytes(implicit))

    @staticmethod
    def verify(
        token: BytesLike, key: PublicKey, footer: bytes = b"", implicit: bytes = b"", max_token_bytes: int = 0
    ) -> bytes:
        """Verifies a token and returns its message."""
        raw = as_bytes(token, "token")
        return _raw_read(lib().cb2_public_verify, key, raw, bytes(footer), bytes(implicit), max_token_bytes)


class Token:
    """Claims tokens: a dict of claims in, a dict of claims out after the rules pass."""

    @staticmethod
    def seal(key: LocalKey, claims: Mapping[str, Any], implicit: bytes = b"") -> str:
        """Seals the claims under a local key; the key id goes into the footer."""
        return _claims_make(lib().cb2_token_seal, key, claims, bytes(implicit))

    @staticmethod
    def sign(secret: SecretKey, claims: Mapping[str, Any], implicit: bytes = b"") -> str:
        """Signs the claims with a secret key; the key id goes into the footer."""
        return _claims_make(lib().cb2_token_sign, secret, claims, bytes(implicit))

    @staticmethod
    def open(token: BytesLike, key: LocalKey, rules: RulesLike, implicit: bytes = b"") -> Claims:
        """Opens a sealed claims token under the rules (a Rules or a mapping)."""
        return _claims_read(lib().cb2_token_open, key, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def verify(token: BytesLike, public: PublicKey, rules: RulesLike, implicit: bytes = b"") -> Claims:
        """Verifies a signed claims token under the rules (a Rules or a mapping)."""
        return _claims_read(lib().cb2_token_verify, public, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def peek_key_id(token: BytesLike) -> str | None:
        """The key id the footer names, unverified; None when there is none."""
        raw = as_bytes(token, "token")
        out = c_void_p()
        check(lib().cb2_peek_key_id(raw, len(raw), ctypes.byref(out)))
        return optional_text(out.value)


def _digest(ptr: int | None) -> bytes | None:
    if not ptr:
        return None
    return take_bytes(ptr, Compact.KEY_DIGEST_BYTES)


def _tabled(plain: _Fn, tabled: _Fn, table: ClaimTable | None) -> _Fn:
    if table is None:
        return plain
    handle = table.handle
    return lambda key, *rest: tabled(key, handle, *rest)


class Compact:
    """Compact claims tokens, the experimental cb3.local and cb3.public formats.

    The same claims, rules and verdicts as Token, with the claims carried
    as strict CBOR and the key id as a KEY_DIGEST_BYTES digest, so the
    token is shorter. Making one refuses with ARGUMENT a custom number
    that is not a canonical int64 integer (1.5, 1e3, -0), a time outside
    years 0000 to 9999 and a cnf that is not a kcb2.local or kcb2.public
    key. A Token never opens here and a Compact token never opens as a
    Token; both are INVALID.

    Every call takes an optional ClaimTable as table=. A token made
    under a table opens only under the same table; without one, an
    implicit assertion that starts with "kcb3.table." is ARGUMENT.
    """

    KEY_DIGEST_BYTES = 16
    """The size of the key digest in the footer."""

    @staticmethod
    def seal(
        key: LocalKey, claims: Mapping[str, Any], implicit: bytes = b"", *, table: ClaimTable | None = None
    ) -> str:
        """Seals the claims under a local key; the digest of its key id goes into the footer."""
        fn = _tabled(lib().cb2_compact_seal, lib().cb2_compact_seal_with_table, table)
        return _claims_make(fn, key, claims, bytes(implicit))

    @staticmethod
    def sign(
        secret: SecretKey, claims: Mapping[str, Any], implicit: bytes = b"", *, table: ClaimTable | None = None
    ) -> str:
        """Signs the claims with a secret key; the digest of its key id goes into the footer."""
        fn = _tabled(lib().cb2_compact_sign, lib().cb2_compact_sign_with_table, table)
        return _claims_make(fn, secret, claims, bytes(implicit))

    @staticmethod
    def open(
        token: BytesLike, key: LocalKey, rules: RulesLike, implicit: bytes = b"", *, table: ClaimTable | None = None
    ) -> Claims:
        """Opens a sealed compact token under the rules (a Rules or a mapping)."""
        fn = _tabled(lib().cb2_compact_open, lib().cb2_compact_open_with_table, table)
        return _claims_read(fn, key, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def verify(
        token: BytesLike, public: PublicKey, rules: RulesLike, implicit: bytes = b"", *, table: ClaimTable | None = None
    ) -> Claims:
        """Verifies a signed compact token under the rules (a Rules or a mapping)."""
        fn = _tabled(lib().cb2_compact_verify, lib().cb2_compact_verify_with_table, table)
        return _claims_read(fn, public, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def peek_key_digest(token: BytesLike) -> bytes | None:
        """The key digest the footer carries, unverified; None when there is none."""
        raw = as_bytes(token, "token")
        out = c_void_p()
        check(lib().cb2_compact_peek_key_digest(raw, len(raw), ctypes.byref(out)))
        return _digest(out.value)

    @staticmethod
    def key_digest(key_id: BytesLike) -> bytes:
        """The digest of a key id, to match against peek_key_digest when choosing a key."""
        raw = as_bytes(key_id, "key_id")
        out = c_void_p()
        check(lib().cb2_compact_key_digest(raw, len(raw), ctypes.byref(out)))
        return _digest(out.value) or b""


def _prove(
    fn: _Fn,
    key: _Key,
    htm: str,
    htu: str,
    access_token: str,
    jti: str,
    now: int,
    lifetime: int,
    nonce: str | None,
) -> str:
    method = as_bytes(htm, "htm")
    target = as_bytes(htu, "htu")
    access = as_bytes(access_token, "access_token")
    proof_id = as_bytes(jti, "jti")
    nonce_raw = None if nonce is None else as_bytes(nonce, "nonce")
    nonce_len = 0 if nonce_raw is None else len(nonce_raw)
    out = c_void_p()
    length = c_size_t()
    check(
        fn(
            key.handle,
            method,
            len(method),
            target,
            len(target),
            nonce_raw,
            nonce_len,
            access,
            len(access),
            proof_id,
            len(proof_id),
            int(now),
            int(lifetime),
            ctypes.byref(out),
            ctypes.byref(length),
        )
    )
    return take_text(out.value, length.value)


class Holder:
    """Holder proofs: a client proves possession of the key its access token is bound to, for one request."""

    @staticmethod
    def prove(
        client_secret: SecretKey,
        htm: str,
        htu: str,
        access_token: str,
        jti: str,
        now: int,
        lifetime: int = 60,
        nonce: str | None = None,
    ) -> str:
        """A public-mode proof under the client's pair for the request (method htm, target htu) and the token."""
        return _prove(lib().cb2_holder_prove, client_secret, htm, htu, access_token, jti, now, lifetime, nonce)

    @staticmethod
    def prove_local(
        proof_key: LocalKey,
        htm: str,
        htu: str,
        access_token: str,
        jti: str,
        now: int,
        lifetime: int = 60,
        nonce: str | None = None,
    ) -> str:
        """A local-mode proof under the kcb2.local proof key the issuer put in cnf of a cb2.local token."""
        return _prove(lib().cb2_holder_prove_local, proof_key, htm, htu, access_token, jti, now, lifetime, nonce)

    @staticmethod
    def normalize_target(uri: str) -> str:
        """The request target as the proof binds it: scheme, host, path."""
        raw = as_bytes(uri, "uri")
        out = c_void_p()
        check(lib().cb2_holder_normalize_target(raw, len(raw), ctypes.byref(out)))
        return take_text(out.value)


class KeyWrap:
    """kcb2.local-wrap: a local key wrapped by another local key."""

    @staticmethod
    def wrap(wrapping: LocalKey, key: LocalKey) -> str:
        """Wraps key under wrapping."""
        out = c_void_p()
        check(lib().cb2_wrap(wrapping.handle, key.handle, ctypes.byref(out)))
        return take_text(out.value)

    @staticmethod
    def unwrap(text: BytesLike, wrapping: LocalKey) -> LocalKey:
        """Recovers the key wrapped under wrapping."""
        raw = as_bytes(text, "text")
        out = c_void_p()
        check(lib().cb2_unwrap(raw, len(raw), wrapping.handle, ctypes.byref(out)))
        return LocalKey(out.value)


class Seal:
    """kcb2.seal: a local key sealed to a recipient's public key."""

    @staticmethod
    def seal(recipient_public: RecipientPublicKey, key: LocalKey) -> str:
        """Seals key to the recipient."""
        out = c_void_p()
        check(lib().cb2_seal(recipient_public.handle, key.handle, ctypes.byref(out)))
        return take_text(out.value)

    @staticmethod
    def unseal(text: BytesLike, recipient: RecipientKey) -> LocalKey:
        """Recovers the key sealed to the recipient."""
        raw = as_bytes(text, "text")
        out = c_void_p()
        check(lib().cb2_unseal(raw, len(raw), recipient.handle, ctypes.byref(out)))
        return LocalKey(out.value)
