from __future__ import annotations

from typing import Any

import pytest
from cb2_testing import CLAIMS, ISSUER, NOW, expect_verdict, requires_public, rules

from cb2 import ClaimTable, Code, Compact, LocalKey, Rules, SecretKey

ENTRIES = [ISSUER, "api", "billing"]
DIGEST = "767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d"
RESERVED = b"kcb3.table."


@pytest.fixture(scope="module")
def table() -> ClaimTable:
    return ClaimTable(ENTRIES)


@pytest.fixture
def key() -> LocalKey:
    return LocalKey.generate()


@pytest.fixture
def tabled(key: LocalKey, table: ClaimTable) -> str:
    return Compact.seal(key, CLAIMS, table=table)


def test_digest(table: ClaimTable) -> None:
    assert table.digest().hex() == DIGEST
    assert len(table.digest()) == ClaimTable.DIGEST_BYTES == 32
    assert ClaimTable(iter(ENTRIES)).digest() == table.digest()
    assert ClaimTable(["api", ISSUER, "billing"]).digest() != table.digest()
    assert table.entries == tuple(ENTRIES)
    assert repr(table) == "<cb2.ClaimTable 3 entries>"


@pytest.mark.parametrize("entries", [[1], [], ["a", "a"], ["a", ""], ["a\nb"], ["a\u200bb"], ["x"] * 257])
def test_refused_entries(entries: list[Any]) -> None:
    expect_verdict(Code.ARGUMENT, ClaimTable, entries)


def test_entries_must_be_a_list_of_strings() -> None:
    bad: Any = "api"
    with pytest.raises(TypeError, match="iterable of str"):
        ClaimTable(bad)
    assert len(ClaimTable([f"e{i}" for i in range(256)]).entries) == 256


def test_shorter_and_same_claims(key: LocalKey, table: ClaimTable, tabled: str) -> None:
    plain = Compact.seal(key, CLAIMS)
    assert tabled.startswith("cb3.local.")
    assert len(tabled) + 30 < len(plain)
    same = ClaimTable(ENTRIES)
    assert Compact.open(tabled, key, rules(), table=same) == Compact.open(plain, key, rules())


def test_opens_only_under_its_table(key: LocalKey, table: ClaimTable, tabled: str) -> None:
    plain = Compact.seal(key, CLAIMS)
    reordered = ClaimTable(["api", ISSUER, "billing"])
    expect_verdict(Code.INVALID, Compact.open, tabled, key, rules())
    expect_verdict(Code.INVALID, Compact.open, tabled, key, rules(), table=None)
    expect_verdict(Code.INVALID, Compact.open, tabled, key, rules(), table=reordered)
    expect_verdict(Code.INVALID, Compact.open, plain, key, rules(), table=table)
    assert Compact.open(plain, key, rules(), table=None)["sub"] == "user-1"


def test_claim_checks_under_a_table(key: LocalKey, table: ClaimTable, tabled: str) -> None:
    billing = Rules(issuer=ISSUER, audience="billing", now=NOW)
    expect_verdict(Code.AUDIENCE_MISMATCH, Compact.open, tabled, key, billing, table=table)
    elsewhere = Rules(issuer="https://other.example", audience="api", now=NOW)
    expect_verdict(Code.ISSUER_MISMATCH, Compact.open, tabled, key, elsewhere, table=table)
    anything = Rules(allow_any_issuer=True, allow_any_audience=True, now=NOW)
    claims = Compact.open(tabled, key, anything, table=table)
    assert (claims["iss"], claims["aud"]) == (ISSUER, "api")
    expect_verdict(Code.REPLAYED, Compact.open, tabled, key, rules(seen_jti=["id-1"]), table=table)


def test_reserved_implicit_assertion(key: LocalKey, table: ClaimTable) -> None:
    plain = Compact.seal(key, CLAIMS)
    expect_verdict(Code.ARGUMENT, Compact.seal, key, CLAIMS, RESERVED)
    expect_verdict(Code.ARGUMENT, Compact.seal, key, CLAIMS, RESERVED, table=None)
    expect_verdict(Code.ARGUMENT, Compact.open, plain, key, rules(), RESERVED)
    with_context = Compact.seal(key, CLAIMS, RESERVED, table=table)
    assert Compact.open(with_context, key, rules(), RESERVED, table=table)["aud"] == "api"
    expect_verdict(Code.INVALID, Compact.open, with_context, key, rules(), table=table)


@requires_public
def test_sign_and_verify_under_a_table(table: ClaimTable) -> None:
    secret = SecretKey.generate()
    public = secret.public_key()
    signed = Compact.sign(secret, CLAIMS, table=table)
    assert signed.startswith("cb3.public.")
    assert len(signed) < len(Compact.sign(secret, CLAIMS))
    assert Compact.verify(signed, public, rules(), table=ClaimTable(ENTRIES))["iss"] == ISSUER
    expect_verdict(Code.INVALID, Compact.verify, signed, public, rules())
    reordered = ClaimTable(["api", ISSUER, "billing"])
    expect_verdict(Code.INVALID, Compact.verify, signed, public, rules(), table=reordered)
