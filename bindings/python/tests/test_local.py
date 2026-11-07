from __future__ import annotations

from typing import Any

import pytest
from cb2_testing import CLAIMS, ISSUER, NOW, expect_verdict, rules

from cb2 import Cb2Error, Code, KeyWrap, Local, LocalKey, Rules, Token


@pytest.fixture
def key() -> LocalKey:
    return LocalKey.generate()


@pytest.fixture
def token(key: LocalKey) -> str:
    return Token.seal(key, CLAIMS)


def test_key_paserk_round_trip(key: LocalKey) -> None:
    paserk = key.to_paserk()
    assert paserk.startswith("kcb2.local.")
    assert len(paserk) == 54
    pid = key.paserk_id()
    assert pid.startswith("kcb2.lid.")
    assert key.key_id == pid
    assert LocalKey.from_paserk(paserk).paserk_id() == pid


def test_raw_round_trip(key: LocalKey) -> None:
    same = LocalKey.from_paserk(key.to_paserk())
    footer = b'{"kid":"x"}'
    token = Local.seal(key, b"hello", footer=footer)
    assert token.startswith("cb2.local.")
    assert Local.open(token, same, footer=footer) == b"hello"
    expect_verdict(Code.INVALID, Local.open, token, same)
    last = "B" if token[-1] == "A" else "A"
    expect_verdict(Code.INVALID, Local.open, token[:-1] + last, same, footer=footer)


def test_claims_round_trip(key: LocalKey, token: str) -> None:
    claims = Token.open(token, key, rules())
    assert claims["role"] == "admin"
    assert claims["jti"] == "id-1"
    assert Token.peek_key_id(token) == key.paserk_id()


def test_token_as_bytes(key: LocalKey, token: str) -> None:
    assert Token.open(token.encode("ascii"), key, rules())["sub"] == "user-1"


def test_rules_as_mapping(key: LocalKey, token: str) -> None:
    claims = Token.open(token, key, {"issuer": ISSUER, "audience": "api", "now": NOW})
    assert claims["sub"] == "user-1"


def test_rules_incomplete(key: LocalKey, token: str) -> None:
    expect_verdict(Code.RULES_INCOMPLETE, Token.open, token, key, Rules())
    expect_verdict(Code.RULES_INCOMPLETE, Token.open, token, key, {})


def test_audience_mismatch(key: LocalKey, token: str) -> None:
    other = Rules(issuer=ISSUER, audience="other", now=NOW)
    expect_verdict(Code.AUDIENCE_MISMATCH, Token.open, token, key, other)


def test_expired(key: LocalKey, token: str) -> None:
    late = Rules(issuer=ISSUER, audience="api", now=4102444801)
    expect_verdict(Code.EXPIRED, Token.open, token, key, late)


def test_replay_callback(key: LocalKey, token: str) -> None:
    seen: list[str] = []

    def remember(jti: str) -> bool:
        if jti in seen:
            return False
        seen.append(jti)
        return True

    claims = Token.open(token, key, rules(replay=remember))
    assert claims["jti"] == "id-1"
    assert seen == ["id-1"]
    expect_verdict(Code.REPLAYED, Token.open, token, key, rules(replay=remember))


def test_replay_callback_exception_refuses(key: LocalKey, token: str) -> None:
    def broken(jti: str) -> bool:
        raise RuntimeError("store down")

    expect_verdict(Code.REPLAYED, Token.open, token, key, rules(replay=broken))


def test_replay_seen_jti(key: LocalKey, token: str) -> None:
    expect_verdict(Code.REPLAYED, Token.open, token, key, rules(seen_jti=["id-1"]))
    assert Token.open(token, key, rules(seen_jti=["id-2"]))["jti"] == "id-1"


def test_lifetime_exceeded(key: LocalKey, token: str) -> None:
    expect_verdict(Code.LIFETIME_EXCEEDED, Token.open, token, key, rules(max_lifetime=60))


def test_rules_must_be_rules_or_mapping(key: LocalKey, token: str) -> None:
    bad: Any = "not json"
    with pytest.raises(TypeError):
        Token.open(token, key, bad)


def test_token_must_be_text_or_bytes(key: LocalKey) -> None:
    bad: Any = 42
    with pytest.raises(TypeError, match="token must be str or bytes"):
        Token.open(bad, key, rules())


def test_identifier_with_zero_width_space_refused(key: LocalKey) -> None:
    bad = {"sub": "a\u200bb", "exp": "2099-01-01T00:00:00+00:00"}
    expect_verdict(Code.ARGUMENT, Token.seal, key, bad)


def test_wrap_and_unwrap(key: LocalKey) -> None:
    wrapping = LocalKey.generate()
    wrapped = KeyWrap.wrap(wrapping, key)
    assert wrapped.startswith("kcb2.local-wrap.")
    assert len(wrapped) == 144
    assert KeyWrap.unwrap(wrapped, wrapping).paserk_id() == key.paserk_id()
    expect_verdict(Code.INVALID, KeyWrap.unwrap, wrapped, key)


def test_key_id(key: LocalKey) -> None:
    key.key_id = "rotation-1"
    assert key.key_id == "rotation-1"
    with pytest.raises(Cb2Error) as caught:
        key.key_id = "a\u200b"
    assert caught.value.code == Code.ARGUMENT
    assert key.key_id == "rotation-1"
    key.clear_key_id()
    assert key.key_id is None
    key.key_id = "rotation-2"
    key.key_id = None
    assert key.key_id is None


def test_weak_key_bytes_refused() -> None:
    expect_verdict(Code.ARGUMENT, LocalKey.from_bytes, bytes([7] * 32))


def test_bad_paserk_refused() -> None:
    with pytest.raises(Cb2Error):
        LocalKey.from_paserk("kcb2.local.nope")
