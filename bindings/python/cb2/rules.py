"""Validation rules for claims tokens and their translation to the ABI."""

from __future__ import annotations

import json
from dataclasses import dataclass, fields
from typing import Any, Callable, Dict, List, Optional, Tuple

from ._lib import ReplayFn

ReplayCheck = Callable[[str], bool]

_CALLBACK_FIELDS = ("replay", "proof_replay")


@dataclass
class Rules:
    """The rules JSON of cb2_token_open as a dataclass.

    Every field is optional and omitted from the JSON when None. replay
    and proof_replay are Python callables taking the jti as str and
    returning True to accept it; seen_jti and proof_seen_jti are the
    built-in list checks and take precedence over the callables.
    """

    issuer: Optional[str] = None
    audience: Optional[str] = None
    subject: Optional[str] = None
    now: Optional[int] = None
    clock_skew: Optional[int] = None
    require_exp: Optional[bool] = None
    allow_any_audience: Optional[bool] = None
    allow_any_issuer: Optional[bool] = None
    max_token_bytes: Optional[int] = None
    max_lifetime: Optional[int] = None
    seen_jti: Optional[List[str]] = None
    require_cnf: Optional[bool] = None
    ignore_cnf: Optional[bool] = None
    proof: Optional[str] = None
    request: Optional[Dict[str, str]] = None
    proof_lifetime: Optional[int] = None
    proof_seen_jti: Optional[List[str]] = None
    replay: Optional[ReplayCheck] = None
    proof_replay: Optional[ReplayCheck] = None

    def to_dict(self) -> Dict[str, Any]:
        """The rules as a plain dict, callables included."""
        out = {}
        for f in fields(self):
            value = getattr(self, f.name)
            if value is not None:
                out[f.name] = value
        return out


def _trampoline(fn: ReplayCheck) -> ReplayFn:
    def call(user, jti, jti_len):
        try:
            raw = (jti or b"")[:jti_len]
            return 1 if fn(raw.decode("utf-8")) else 0
        except Exception:
            return 0

    return ReplayFn(call)


def prepare(rules) -> Tuple[bytes, ReplayFn, ReplayFn]:
    """Splits rules into the JSON bytes and the two C callbacks.

    A callback the rules do not carry comes back as a null function
    pointer. The returned callback objects must stay referenced for as
    long as the C call that uses them runs.
    """
    if isinstance(rules, Rules):
        source = rules.to_dict()
    elif isinstance(rules, dict):
        source = dict(rules)
    else:
        raise TypeError("rules must be a Rules or a dict, not %s" % type(rules).__name__)
    given = {name: source.pop(name, None) for name in _CALLBACK_FIELDS}
    if given["replay"]:
        source["replay"] = True
    text = json.dumps(source, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return text, _callback(given["replay"]), _callback(given["proof_replay"])


def _callback(value) -> ReplayFn:
    if callable(value):
        return _trampoline(value)
    return ReplayFn()
