from __future__ import annotations

from cb2_testing import expect_verdict, requires_seal

from cb2 import Code, LocalKey, RecipientKey, RecipientPublicKey, Seal

pytestmark = requires_seal


def test_seal_and_unseal() -> None:
    recipient = RecipientKey.generate()
    public = recipient.public_key()
    text = public.to_paserk()
    assert len(text) == 1637
    assert text.startswith("kcb2.recipient.")
    secret = recipient.to_paserk()
    assert len(secret) == 65
    restored = RecipientKey.from_paserk(secret)

    key = LocalKey.generate()
    sealed = Seal.seal(public, key)
    assert len(sealed) == 1632
    assert Seal.unseal(sealed, restored).paserk_id() == key.paserk_id()
    expect_verdict(Code.INVALID, Seal.unseal, sealed, RecipientKey.generate())

    rid = public.paserk_id()
    assert rid == restored.paserk_id()
    assert rid.startswith("kcb2.rid.")
    assert RecipientPublicKey.from_paserk(text).paserk_id() == rid
