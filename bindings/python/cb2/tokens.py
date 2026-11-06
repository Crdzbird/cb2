"""Raw and claims tokens, holder proofs, key wrapping and sealing."""

from __future__ import annotations

import ctypes
import json
from ctypes import c_size_t, c_void_p
from typing import Any, Dict, Optional

from ._lib import as_bytes, lib, optional_text, take_bytes, take_text
from .errors import check
from .keys import LocalKey, PublicKey, RecipientKey, RecipientPublicKey, SecretKey
from .rules import prepare


def _raw_make(fn, key, msg: bytes, footer: bytes, implicit: bytes) -> str:
    out = c_void_p()
    length = c_size_t()
    check(fn(key.handle, msg, len(msg), footer, len(footer), implicit, len(implicit), ctypes.byref(out), ctypes.byref(length)))
    return take_text(out.value, length.value)


def _raw_read(fn, key, token: bytes, footer: bytes, implicit: bytes, max_token_bytes: int) -> bytes:
    out = c_void_p()
    length = c_size_t()
    check(fn(key.handle, token, len(token), footer, len(footer), implicit, len(implicit), max_token_bytes, ctypes.byref(out), ctypes.byref(length)))
    return take_bytes(out.value, length.value)


def _claims_json(claims: Dict[str, Any]) -> bytes:
    return json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _claims_make(fn, key, claims: Dict[str, Any], implicit: bytes) -> str:
    text = _claims_json(claims)
    out = c_void_p()
    length = c_size_t()
    check(fn(key.handle, text, len(text), implicit, len(implicit), ctypes.byref(out), ctypes.byref(length)))
    return take_text(out.value, length.value)


def _claims_read(fn, key, token: bytes, rules, implicit: bytes) -> Dict[str, Any]:
    rules_json, replay, proof_replay = prepare(rules)
    keep = (replay, proof_replay)
    out = c_void_p()
    length = c_size_t()
    code = fn(key.handle, token, len(token), rules_json, len(rules_json), implicit, len(implicit), replay, proof_replay, None, ctypes.byref(out), ctypes.byref(length))
    del keep
    check(code)
    return json.loads(take_text(out.value, length.value))


class Local:
    """cb2.local raw tokens: any bytes, encrypted and authenticated."""

    @staticmethod
    def seal(key: LocalKey, msg: bytes, footer: bytes = b"", implicit: bytes = b"") -> str:
        """Seals msg under key with an optional footer and implicit assertion."""
        return _raw_make(lib().cb2_local_seal, key, bytes(msg), bytes(footer), bytes(implicit))

    @staticmethod
    def open(token: str, key: LocalKey, footer: bytes = b"", implicit: bytes = b"", max_token_bytes: int = 0) -> bytes:
        """Opens a token; the footer and implicit assertion must match."""
        return _raw_read(lib().cb2_local_open, key, as_bytes(token, "token"), bytes(footer), bytes(implicit), max_token_bytes)


class Public:
    """cb2.public raw tokens: any bytes, signed."""

    @staticmethod
    def sign(key: SecretKey, msg: bytes, footer: bytes = b"", implicit: bytes = b"") -> str:
        """Signs msg with the pair, with an optional footer and implicit assertion."""
        return _raw_make(lib().cb2_public_sign, key, bytes(msg), bytes(footer), bytes(implicit))

    @staticmethod
    def verify(token: str, key: PublicKey, footer: bytes = b"", implicit: bytes = b"", max_token_bytes: int = 0) -> bytes:
        """Verifies a token and returns its message."""
        return _raw_read(lib().cb2_public_verify, key, as_bytes(token, "token"), bytes(footer), bytes(implicit), max_token_bytes)


class Token:
    """Claims tokens: a dict of claims in, a dict of claims out after the rules pass."""

    @staticmethod
    def seal(key: LocalKey, claims: Dict[str, Any], implicit: bytes = b"") -> str:
        """Seals the claims under a local key; the key id goes into the footer."""
        return _claims_make(lib().cb2_token_seal, key, claims, bytes(implicit))

    @staticmethod
    def sign(secret: SecretKey, claims: Dict[str, Any], implicit: bytes = b"") -> str:
        """Signs the claims with a secret key; the key id goes into the footer."""
        return _claims_make(lib().cb2_token_sign, secret, claims, bytes(implicit))

    @staticmethod
    def open(token: str, key: LocalKey, rules, implicit: bytes = b"") -> Dict[str, Any]:
        """Opens a sealed claims token under the rules (a Rules or a dict)."""
        return _claims_read(lib().cb2_token_open, key, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def verify(token: str, public: PublicKey, rules, implicit: bytes = b"") -> Dict[str, Any]:
        """Verifies a signed claims token under the rules (a Rules or a dict)."""
        return _claims_read(lib().cb2_token_verify, public, as_bytes(token, "token"), rules, bytes(implicit))

    @staticmethod
    def peek_key_id(token: str) -> Optional[str]:
        """The key id the footer names, unverified; None when there is none."""
        raw = as_bytes(token, "token")
        out = c_void_p()
        check(lib().cb2_peek_key_id(raw, len(raw), ctypes.byref(out)))
        return optional_text(out.value)


def _prove(fn, handle, htm: str, htu: str, access_token: str, jti: str, now: int, lifetime: int, nonce: Optional[str]) -> str:
    method = as_bytes(htm, "htm")
    target = as_bytes(htu, "htu")
    access = as_bytes(access_token, "access_token")
    proof_id = as_bytes(jti, "jti")
    nonce_raw = None if nonce is None else as_bytes(nonce, "nonce")
    nonce_len = 0 if nonce_raw is None else len(nonce_raw)
    out = c_void_p()
    length = c_size_t()
    check(fn(handle, method, len(method), target, len(target), nonce_raw, nonce_len, access, len(access), proof_id, len(proof_id), int(now), int(lifetime), ctypes.byref(out), ctypes.byref(length)))
    return take_text(out.value, length.value)


class Holder:
    """Holder proofs: a client proves possession of the key its access token is bound to, for one request."""

    @staticmethod
    def prove(client_secret: SecretKey, htm: str, htu: str, access_token: str, jti: str, now: int, lifetime: int = 60, nonce: Optional[str] = None) -> str:
        """A public-mode proof under the client's pair for the request (method htm, target htu) and the access token."""
        return _prove(lib().cb2_holder_prove, client_secret.handle, htm, htu, access_token, jti, now, lifetime, nonce)

    @staticmethod
    def prove_local(proof_key: LocalKey, htm: str, htu: str, access_token: str, jti: str, now: int, lifetime: int = 60, nonce: Optional[str] = None) -> str:
        """A local-mode proof under the kcb2.local proof key the issuer put in cnf of a cb2.local access token; every build."""
        return _prove(lib().cb2_holder_prove_local, proof_key.handle, htm, htu, access_token, jti, now, lifetime, nonce)

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
    def unwrap(text: str, wrapping: LocalKey) -> LocalKey:
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
    def unseal(text: str, recipient: RecipientKey) -> LocalKey:
        """Recovers the key sealed to the recipient."""
        raw = as_bytes(text, "text")
        out = c_void_p()
        check(lib().cb2_unseal(raw, len(raw), recipient.handle, ctypes.byref(out)))
        return LocalKey(out.value)
