from __future__ import annotations

import pytest
from cb2_testing import CLAIMS, ISSUER, NOW, TARGET, bound_claims, expect_verdict, requires_public, rules

from cb2 import Code, Holder, LocalKey, Public, PublicKey, Rules, SecretKey, Token

pytestmark = requires_public


@pytest.fixture(scope="module")
def secret() -> SecretKey:
    return SecretKey.generate()


@pytest.fixture(scope="module")
def stranger() -> SecretKey:
    return SecretKey.generate()


def test_public_key_paserk(secret: SecretKey) -> None:
    public = secret.public_key()
    text = public.to_paserk()
    assert len(text) == 2658
    assert text.startswith("kcb2.public.")
    assert PublicKey.from_paserk(text).paserk_id() == public.paserk_id()
    assert secret.paserk_id() == public.paserk_id()
    assert secret.to_paserk().startswith("kcb2.secret.")


def test_sign_and_verify_claims(secret: SecretKey, stranger: SecretKey) -> None:
    token = Token.sign(secret, CLAIMS)
    public = PublicKey.from_paserk(secret.public_key().to_paserk())
    assert Token.verify(token, public, rules())["role"] == "admin"
    expect_verdict(Code.INVALID, Token.verify, token, stranger.public_key(), rules())


def test_raw_sign_and_verify(secret: SecretKey, stranger: SecretKey) -> None:
    public = secret.public_key()
    token = Public.sign(secret, b"hello", footer=b"f", implicit=b"i")
    assert token.startswith("cb2.public.")
    assert Public.verify(token, public, footer=b"f", implicit=b"i") == b"hello"
    expect_verdict(Code.INVALID, Public.verify, token, public, footer=b"f")
    expect_verdict(Code.INVALID, Public.verify, token, stranger.public_key(), footer=b"f", implicit=b"i")


def test_bound_token_and_holder_proof(stranger: SecretKey) -> None:
    key = LocalKey.generate()
    cnf = stranger.public_key().to_paserk()
    access = Token.seal(key, bound_claims(cnf))
    expect_verdict(Code.MISSING_PROOF, Token.open, access, key, rules())

    proof = Holder.prove(stranger, "GET", TARGET, access, "p-1", NOW)
    assert proof.startswith("cb2.holder-public.")
    request = {"htm": "GET", "htu": "HTTPS://API.EXAMPLE:443/v1/me?x=1"}
    expect_verdict(Code.RULES_INCOMPLETE, Token.open, access, key, rules(proof=proof, request=request))
    claims = Token.open(access, key, rules(proof=proof, request=request, proof_replay=lambda jti: True))
    assert claims["aud"] == "api"

    seen: list[str] = []

    def remember(jti: str) -> bool:
        if jti in seen:
            return False
        seen.append(jti)
        return True

    plain = {"htm": "GET", "htu": TARGET}
    Token.open(access, key, rules(proof=proof, request=plain, proof_replay=remember))
    assert seen == ["p-1"]
    expect_verdict(
        Code.PROOF_REPLAYED, Token.open, access, key, rules(proof=proof, request=plain, proof_replay=remember)
    )
    wrong = {"htm": "POST", "htu": TARGET}
    expect_verdict(Code.PROOF_MISMATCH, Token.open, access, key, rules(proof=proof, request=wrong, proof_seen_jti=[]))
    replayed = rules(proof=proof, request=plain, proof_seen_jti=["p-1"])
    expect_verdict(Code.PROOF_REPLAYED, Token.open, access, key, replayed)
    stale = Rules(issuer=ISSUER, audience="api", now=NOW + 100, proof=proof, request=plain, proof_seen_jti=[])
    expect_verdict(Code.PROOF_EXPIRED, Token.open, access, key, stale)
    assert Token.open(access, key, rules(ignore_cnf=True))["cnf"] == cnf


def test_secret_key_id() -> None:
    secret = SecretKey.generate()
    public = secret.public_key()
    secret.key_id = "client-1"
    assert secret.key_id == "client-1"
    secret.clear_key_id()
    assert secret.key_id is None
    assert public.key_id == public.paserk_id()
    public.clear_key_id()
    assert public.key_id is None
