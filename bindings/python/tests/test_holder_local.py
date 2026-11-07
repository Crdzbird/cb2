from __future__ import annotations

from cb2_testing import ISSUER, NOW, TARGET, bound_claims, expect_verdict, rules

from cb2 import Code, Holder, LocalKey, Rules, Token


def test_local_proof_key_in_cnf() -> None:
    key = LocalKey.generate()
    proof_key = LocalKey.generate()
    bound = bound_claims(proof_key.to_paserk())
    access = Token.seal(key, bound)
    expect_verdict(Code.MISSING_PROOF, Token.open, access, key, rules())

    client = LocalKey.from_paserk(bound["cnf"])
    proof = Holder.prove_local(client, "GET", TARGET, access, "p-1", NOW)
    assert proof.startswith("cb2.holder-local.")
    assert len(proof) < 450

    request = {"htm": "GET", "htu": "HTTPS://API.EXAMPLE:443/v1/me?x=1"}
    expect_verdict(Code.RULES_INCOMPLETE, Token.open, access, key, rules(proof=proof, request=request))
    claims = Token.open(access, key, rules(proof=proof, request=request, proof_replay=lambda jti: True))
    assert claims["aud"] == "api"

    plain = {"htm": "GET", "htu": TARGET}
    seen = ["p-1"]
    expect_verdict(Code.PROOF_REPLAYED, Token.open, access, key, rules(proof=proof, request=plain, proof_seen_jti=seen))
    wrong = {"htm": "POST", "htu": TARGET}
    expect_verdict(Code.PROOF_MISMATCH, Token.open, access, key, rules(proof=proof, request=wrong, proof_seen_jti=[]))
    forged = Holder.prove_local(LocalKey.generate(), "GET", TARGET, access, "p-2", NOW)
    expect_verdict(Code.PROOF_INVALID, Token.open, access, key, rules(proof=forged, request=plain, proof_seen_jti=[]))
    stale = Rules(issuer=ISSUER, audience="api", now=NOW + 100, proof=proof, request=plain, proof_seen_jti=[])
    expect_verdict(Code.PROOF_EXPIRED, Token.open, access, key, stale)
    expect_verdict(Code.ARGUMENT, Holder.prove_local, client, "GET", "nope", access, "p-3", NOW)


def test_normalize_target() -> None:
    assert Holder.normalize_target("HTTPS://API.Example:443/a?b#c") == "https://api.example/a"
    expect_verdict(Code.ARGUMENT, Holder.normalize_target, "nope")
