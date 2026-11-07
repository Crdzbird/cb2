"""Shared constants and the verdict assertion for the cb2 tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

import cb2
from cb2 import Cb2Error, Code, Rules

ISSUER = "https://issuer.example"
NOW = 1700000000
TARGET = "https://api.example/v1/me"

CLAIMS: dict[str, Any] = {
    "iss": ISSUER,
    "sub": "user-1",
    "aud": "api",
    "exp": "2099-01-01T00:00:00+00:00",
    "jti": "id-1",
    "role": "admin",
}

requires_public = pytest.mark.skipif(not cb2.has_public(), reason="cb2.public unavailable in this build")
requires_seal = pytest.mark.skipif(not cb2.has_seal(), reason="kcb2.seal unavailable in this build")


def rules(**extra: Any) -> Rules:
    """The rules every test starts from: the issuer, the audience and a fixed clock."""
    return Rules(issuer=ISSUER, audience="api", now=NOW, **extra)


def bound_claims(cnf: str) -> dict[str, Any]:
    """Claims of an access token bound to the key in cnf."""
    return {"iss": ISSUER, "aud": "api", "exp": "2099-01-01T00:00:00+00:00", "cnf": cnf}


def expect_verdict(code: Code, fn: Callable[..., object], *args: Any, **kwargs: Any) -> Cb2Error:
    """Calls fn and asserts that it raises the verdict code with its stable name."""
    with pytest.raises(Cb2Error) as caught:
        fn(*args, **kwargs)
    assert caught.value.code == int(code)
    assert caught.value.name == cb2.error_name(code)
    return caught.value
