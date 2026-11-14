from __future__ import annotations

from typing import Any

import pytest
from cb2_testing import CLAIMS, ISSUER, NOW, TARGET, bound_claims, expect_verdict, requires_public, rules

import cb2
from cb2 import Code, Compact, Holder, LocalKey, Rules, SecretKey, Token


@pytest.fixture
def key() -> LocalKey:
    return LocalKey.generate()


@pytest.fixture
def token(key: LocalKey) -> str:
    return Compact.seal(key, CLAIMS)


def test_shorter_than_cb2_with_the_same_claims(key: LocalKey, token: str) -> None:
    full = Token.seal(key, CLAIMS)
    assert token.startswith("cb3.local.")
    assert len(token) < len(full)
    claims = Compact.open(token, key, rules())
    assert claims == Token.open(full, key, rules())
    assert claims["role"] == "admin"
    assert Compact.open(token.encode("ascii"), key, {"issuer": ISSUER, "audience": "api", "now": NOW}) == claims


def test_formats_do_not_cross(key: LocalKey, token: str) -> None:
    full = Token.seal(key, CLAIMS)
    expect_verdict(Code.INVALID, Token.open, token, key, rules())
    expect_verdict(Code.INVALID, Compact.open, full, key, rules())
    expect_verdict(Code.INVALID, Compact.open, token, LocalKey.generate(), rules())
    expect_verdict(Code.INVALID, Compact.open, token, key, rules(), implicit=b"x")


def test_verdicts(key: LocalKey, token: str) -> None:
    expect_verdict(Code.RULES_INCOMPLETE, Compact.open, token, key, Rules())
    expect_verdict(Code.AUDIENCE_MISMATCH, Compact.open, token, key, Rules(issuer=ISSUER, audience="web", now=NOW))
    expect_verdict(Code.EXPIRED, Compact.open, token, key, Rules(issuer=ISSUER, audience="api", now=4102444800))
    expect_verdict(Code.REPLAYED, Compact.open, token, key, rules(seen_jti=["id-1"]))


def test_replay_callback(key: LocalKey, token: str) -> None:
    seen: list[str] = []

    def remember(jti: str) -> bool:
        if jti in seen:
            return False
        seen.append(jti)
        return True

    assert Compact.open(token, key, rules(replay=remember))["jti"] == "id-1"
    assert seen == ["id-1"]
    expect_verdict(Code.REPLAYED, Compact.open, token, key, rules(replay=remember))


def test_key_digest(key: LocalKey, token: str) -> None:
    peeked = Compact.peek_key_digest(token)
    assert peeked is not None
    assert len(peeked) == Compact.KEY_DIGEST_BYTES == 16
    assert key.key_id is not None
    assert peeked == Compact.key_digest(key.key_id)
    assert Compact.key_digest(key.key_id.encode("utf-8")) == peeked
    assert Compact.peek_key_digest(Token.seal(key, CLAIMS)) is None
    assert len(Compact.key_digest("")) == Compact.KEY_DIGEST_BYTES
    expect_verdict(Code.ARGUMENT, Compact.key_digest, "a\nb")


def test_key_without_an_id(key: LocalKey, token: str) -> None:
    key.clear_key_id()
    bare = Compact.seal(key, CLAIMS)
    assert Compact.peek_key_digest(bare) is None
    assert len(bare) < len(token)
    expect_verdict(Code.INVALID, Compact.open, token, key, rules())
    assert Compact.open(bare, key, rules())["sub"] == "user-1"


@pytest.mark.parametrize("number", [1.5, 1000.0, -0.0, 2**63])
def test_number_outside_the_profile_refused(key: LocalKey, number: float) -> None:
    claims = {**CLAIMS, "n": number}
    expect_verdict(Code.ARGUMENT, Compact.seal, key, claims)
    assert Token.open(Token.seal(key, claims), key, rules())["n"] == number


def test_integers_and_structures_round_trip(key: LocalKey) -> None:
    custom: dict[str, Any] = {"small": -7, "max": 2**63 - 1, "min": -(2**63), "flag": True, "list": [1, "a"]}
    claims = Compact.open(Compact.seal(key, {**CLAIMS, **custom}), key, rules())
    assert {name: claims[name] for name in custom} == custom


def test_bad_arguments(key: LocalKey, token: str) -> None:
    bad: Any = 42
    with pytest.raises(TypeError, match="token must be str or bytes"):
        Compact.open(bad, key, rules())
    with pytest.raises(TypeError, match="key_id must be str or bytes"):
        Compact.key_digest(bad)
    expect_verdict(Code.ARGUMENT, Compact.seal, key, {"sub": "a\u200bb", "exp": "2099-01-01T00:00:00+00:00"})


def test_bound_to_a_local_proof_key(key: LocalKey) -> None:
    proof_key = LocalKey.generate()
    cnf = proof_key.to_paserk()
    access = Compact.seal(key, bound_claims(cnf))
    expect_verdict(Code.MISSING_PROOF, Compact.open, access, key, rules())

    proof = Holder.prove_local(proof_key, "GET", TARGET, access, "p-1", NOW)
    request = {"htm": "GET", "htu": TARGET}
    claims = Compact.open(access, key, rules(proof=proof, request=request, proof_replay=lambda jti: True))
    assert claims["cnf"] == cnf
    wrong = {"htm": "POST", "htu": TARGET}
    expect_verdict(Code.PROOF_MISMATCH, Compact.open, access, key, rules(proof=proof, request=wrong, proof_seen_jti=[]))
    expect_verdict(
        Code.PROOF_REPLAYED, Compact.open, access, key, rules(proof=proof, request=request, proof_seen_jti=["p-1"])
    )


@requires_public
def test_sign_and_verify() -> None:
    secret = SecretKey.generate()
    public = secret.public_key()
    signed = Compact.sign(secret, CLAIMS)
    full = Token.sign(secret, CLAIMS)
    assert signed.startswith("cb3.public.")
    assert len(signed) < len(full)
    assert Compact.verify(signed, public, rules())["role"] == "admin"
    expect_verdict(Code.INVALID, Token.verify, signed, public, rules())
    expect_verdict(Code.INVALID, Compact.verify, full, public, rules())
    expect_verdict(Code.INVALID, Compact.verify, signed, SecretKey.generate().public_key(), rules())
    expect_verdict(
        Code.AUDIENCE_MISMATCH, Compact.verify, signed, public, Rules(issuer=ISSUER, audience="web", now=NOW)
    )
    assert Compact.peek_key_digest(signed) == Compact.key_digest(public.paserk_id())
    expect_verdict(Code.ARGUMENT, Compact.sign, secret, bound_claims("not a key"))


@pytest.mark.skipif(cb2.has_public(), reason="this build has cb2.public")
def test_public_unavailable_without_liboqs(key: LocalKey, token: str) -> None:
    with pytest.raises(cb2.Cb2Error) as caught:
        SecretKey.generate()
    assert caught.value.code == Code.UNAVAILABLE
    assert Compact.open(token, key, rules())["sub"] == "user-1"
