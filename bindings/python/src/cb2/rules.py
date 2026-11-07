"""Validation rules for claims tokens and their translation to the ABI."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields
from typing import Any

from ._lib import ReplayFn

ReplayCheck = Callable[[str], bool]
"""A replay check: takes the jti and returns True to accept it, False to refuse it."""

_CALLBACK_FIELDS = ("replay", "proof_replay")


@dataclass(frozen=True)
class Rules:
    """The rules JSON of cb2_token_open as a dataclass.

    Every field is optional and omitted from the JSON when None. replay
    and proof_replay are Python callables taking the jti as str and
    returning True to accept it; an exception raised inside one refuses
    the token. seen_jti and proof_seen_jti are the built-in list checks
    and take precedence over the callables.
    """

    issuer: str | None = None
    audience: str | None = None
    subject: str | None = None
    now: int | None = None
    clock_skew: int | None = None
    require_exp: bool | None = None
    allow_any_audience: bool | None = None
    allow_any_issuer: bool | None = None
    max_token_bytes: int | None = None
    max_lifetime: int | None = None
    seen_jti: list[str] | None = None
    require_cnf: bool | None = None
    ignore_cnf: bool | None = None
    proof: str | None = None
    request: dict[str, str] | None = None
    proof_lifetime: int | None = None
    proof_seen_jti: list[str] | None = None
    replay: ReplayCheck | None = None
    proof_replay: ReplayCheck | None = None

    def to_dict(self) -> dict[str, Any]:
        """The rules as a plain dict without the None fields, callables included."""
        out: dict[str, Any] = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if value is not None:
                out[f.name] = value
        return out


RulesLike = Rules | Mapping[str, Any]
"""Rules as a Rules instance or as a mapping with the same keys."""


def _trampoline(fn: ReplayCheck) -> Any:
    def call(user: int | None, jti: bytes | None, jti_len: int) -> int:
        try:
            raw = (jti or b"")[:jti_len]
            return 1 if fn(raw.decode("utf-8")) else 0
        except Exception:
            return 0

    return ReplayFn(call)


def _callback(value: object) -> Any:
    if callable(value):
        return _trampoline(value)
    return ReplayFn()


def prepare(rules: RulesLike) -> tuple[bytes, Any, Any]:
    """Splits rules into the JSON bytes and the two C callbacks.

    A callback the rules do not carry comes back as a null function
    pointer. The returned callback objects must stay referenced for as
    long as the C call that uses them runs.
    """
    if isinstance(rules, Rules):
        source = rules.to_dict()
    elif isinstance(rules, Mapping):
        source = dict(rules)
    else:
        raise TypeError(f"rules must be a Rules or a mapping, not {type(rules).__name__}")
    given = {name: source.pop(name, None) for name in _CALLBACK_FIELDS}
    if given["replay"]:
        source["replay"] = True
    text = json.dumps(source, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return text, _callback(given["replay"]), _callback(given["proof_replay"])
