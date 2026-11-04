"""The Python bridge exercised the way bindings/c/test/test_c.c exercises the ABI."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cb2
from cb2 import Cb2Error, Code, Holder, KeyWrap, Local, LocalKey, Public, RecipientKey, Rules, Seal, SecretKey, Token

CLAIMS = {
    "iss": "https://issuer.example",
    "sub": "user-1",
    "aud": "api",
    "exp": "2099-01-01T00:00:00+00:00",
    "jti": "id-1",
    "role": "admin",
}

NOW = 1700000000


def rules(**extra) -> Rules:
    return Rules(issuer="https://issuer.example", audience="api", now=NOW, **extra)


class Verdicts(unittest.TestCase):
    def assertVerdict(self, code: Code, fn, *args, **kwargs):
        with self.assertRaises(Cb2Error) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, int(code))
        self.assertEqual(caught.exception.name, cb2.error_name(code))
        return caught.exception


class LibraryTest(Verdicts):
    def test_version_and_names(self):
        self.assertTrue(cb2.version())
        self.assertIsInstance(cb2.has_public(), bool)
        self.assertIsInstance(cb2.has_seal(), bool)
        self.assertEqual(cb2.error_name(Code.ARGUMENT), "argument")
        self.assertEqual(cb2.error_name(0), "ok")
        self.assertEqual(cb2.error_name(Code.PROOF_REPLAYED), "proof_replayed")
        self.assertEqual(cb2.error_name(99), "unknown")


class LocalTest(Verdicts):
    def setUp(self):
        self.key = LocalKey.generate()
        self.token = Token.seal(self.key, CLAIMS)

    def test_key_paserk_round_trip(self):
        paserk = self.key.to_paserk()
        self.assertTrue(paserk.startswith("kcb2.local."))
        self.assertEqual(len(paserk), 54)
        pid = self.key.paserk_id()
        self.assertTrue(pid.startswith("kcb2.lid."))
        self.assertEqual(self.key.key_id, pid)
        same = LocalKey.from_paserk(paserk)
        self.assertEqual(same.paserk_id(), pid)

    def test_raw_round_trip(self):
        same = LocalKey.from_paserk(self.key.to_paserk())
        footer = b'{"kid":"x"}'
        token = Local.seal(self.key, b"hello", footer=footer)
        self.assertTrue(token.startswith("cb2.local."))
        self.assertEqual(Local.open(token, same, footer=footer), b"hello")
        self.assertVerdict(Code.INVALID, Local.open, token, same)
        last = "B" if token[-1] == "A" else "A"
        self.assertVerdict(Code.INVALID, Local.open, token[:-1] + last, same, footer=footer)

    def test_claims_round_trip(self):
        claims = Token.open(self.token, self.key, rules())
        self.assertEqual(claims["role"], "admin")
        self.assertEqual(claims["jti"], "id-1")
        self.assertEqual(Token.peek_key_id(self.token), self.key.paserk_id())

    def test_rules_as_dict(self):
        claims = Token.open(self.token, self.key, {"issuer": "https://issuer.example", "audience": "api", "now": NOW})
        self.assertEqual(claims["sub"], "user-1")

    def test_rules_incomplete(self):
        self.assertVerdict(Code.RULES_INCOMPLETE, Token.open, self.token, self.key, Rules())
        self.assertVerdict(Code.RULES_INCOMPLETE, Token.open, self.token, self.key, {})

    def test_audience_mismatch(self):
        other = Rules(issuer="https://issuer.example", audience="other", now=NOW)
        self.assertVerdict(Code.AUDIENCE_MISMATCH, Token.open, self.token, self.key, other)

    def test_expired(self):
        late = Rules(issuer="https://issuer.example", audience="api", now=4102444801)
        self.assertVerdict(Code.EXPIRED, Token.open, self.token, self.key, late)

    def test_replay_callback(self):
        seen = []

        def remember(jti: str) -> bool:
            if jti in seen:
                return False
            seen.append(jti)
            return True

        claims = Token.open(self.token, self.key, rules(replay=remember))
        self.assertEqual(claims["jti"], "id-1")
        self.assertEqual(seen, ["id-1"])
        self.assertVerdict(Code.REPLAYED, Token.open, self.token, self.key, rules(replay=remember))

    def test_replay_callback_exception_refuses(self):
        def broken(jti: str) -> bool:
            raise RuntimeError("store down")

        self.assertVerdict(Code.REPLAYED, Token.open, self.token, self.key, rules(replay=broken))

    def test_replay_seen_jti(self):
        self.assertVerdict(Code.REPLAYED, Token.open, self.token, self.key, rules(seen_jti=["id-1"]))
        claims = Token.open(self.token, self.key, rules(seen_jti=["id-2"]))
        self.assertEqual(claims["jti"], "id-1")

    def test_lifetime_exceeded(self):
        self.assertVerdict(Code.LIFETIME_EXCEEDED, Token.open, self.token, self.key, rules(max_lifetime=60))

    def test_rules_must_be_rules_or_dict(self):
        with self.assertRaises(TypeError):
            Token.open(self.token, self.key, "not json")

    def test_identifier_with_zero_width_space_refused(self):
        bad = {"sub": "a\u200bb", "exp": "2099-01-01T00:00:00+00:00"}
        self.assertVerdict(Code.ARGUMENT, Token.seal, self.key, bad)

    def test_wrap_and_unwrap(self):
        wrapping = LocalKey.generate()
        wrapped = KeyWrap.wrap(wrapping, self.key)
        self.assertTrue(wrapped.startswith("kcb2.local-wrap."))
        self.assertEqual(len(wrapped), 144)
        unwrapped = KeyWrap.unwrap(wrapped, wrapping)
        self.assertEqual(unwrapped.paserk_id(), self.key.paserk_id())
        self.assertVerdict(Code.INVALID, KeyWrap.unwrap, wrapped, self.key)

    def test_key_id(self):
        self.key.key_id = "rotation-1"
        self.assertEqual(self.key.key_id, "rotation-1")
        with self.assertRaises(Cb2Error) as caught:
            self.key.key_id = "a\u200b"
        self.assertEqual(caught.exception.code, Code.ARGUMENT)
        self.assertEqual(self.key.key_id, "rotation-1")
        self.key.clear_key_id()
        self.assertIsNone(self.key.key_id)
        self.key.key_id = "rotation-2"
        self.key.key_id = None
        self.assertIsNone(self.key.key_id)

    def test_weak_key_bytes_refused(self):
        self.assertVerdict(Code.ARGUMENT, LocalKey.from_bytes, bytes([7] * 32))

    def test_bad_paserk_refused(self):
        with self.assertRaises(Cb2Error):
            LocalKey.from_paserk("kcb2.local.nope")


@unittest.skipUnless(cb2.has_public(), "cb2.public unavailable in this build")
class PublicTest(Verdicts):
    def setUp(self):
        self.sk = SecretKey.generate()
        self.pk = self.sk.public_key()
        self.stranger = SecretKey.generate()
        self.spk = self.stranger.public_key()

    def test_public_key_paserk(self):
        pub = self.pk.to_paserk()
        self.assertEqual(len(pub), 2658)
        self.assertTrue(pub.startswith("kcb2.public."))
        self.assertEqual(cb2.PublicKey.from_paserk(pub).paserk_id(), self.pk.paserk_id())
        self.assertEqual(self.sk.paserk_id(), self.pk.paserk_id())
        self.assertTrue(self.sk.to_paserk().startswith("kcb2.secret."))

    def test_sign_and_verify_claims(self):
        token = Token.sign(self.sk, CLAIMS)
        pk2 = cb2.PublicKey.from_paserk(self.pk.to_paserk())
        claims = Token.verify(token, pk2, rules())
        self.assertEqual(claims["role"], "admin")
        self.assertVerdict(Code.INVALID, Token.verify, token, self.spk, rules())

    def test_raw_sign_and_verify(self):
        token = Public.sign(self.sk, b"hello", footer=b"f", implicit=b"i")
        self.assertTrue(token.startswith("cb2.public."))
        self.assertEqual(Public.verify(token, self.pk, footer=b"f", implicit=b"i"), b"hello")
        self.assertVerdict(Code.INVALID, Public.verify, token, self.pk, footer=b"f")
        self.assertVerdict(Code.INVALID, Public.verify, token, self.spk, footer=b"f", implicit=b"i")

    def test_bound_token_and_holder_proof(self):
        key = LocalKey.generate()
        bound = {
            "iss": "https://issuer.example",
            "aud": "api",
            "exp": "2099-01-01T00:00:00+00:00",
            "cnf": self.spk.to_paserk(),
        }
        access = Token.seal(key, bound)
        self.assertVerdict(Code.MISSING_PROOF, Token.open, access, key, rules())
        proof = Holder.prove(self.stranger, "GET", "https://api.example/v1/me", access, "p-1", NOW)
        self.assertTrue(proof.startswith("cb2.holder-public."))
        request = {"htm": "GET", "htu": "HTTPS://API.EXAMPLE:443/v1/me?x=1"}
        self.assertVerdict(Code.RULES_INCOMPLETE, Token.open, access, key, rules(proof=proof, request=request))
        claims = Token.open(access, key, rules(proof=proof, request=request, proof_replay=lambda jti: True))
        self.assertEqual(claims["aud"], "api")
        seen = []

        def remember(jti: str) -> bool:
            if jti in seen:
                return False
            seen.append(jti)
            return True

        plain = {"htm": "GET", "htu": "https://api.example/v1/me"}
        Token.open(access, key, rules(proof=proof, request=plain, proof_replay=remember))
        self.assertEqual(seen, ["p-1"])
        self.assertVerdict(Code.PROOF_REPLAYED, Token.open, access, key, rules(proof=proof, request=plain, proof_replay=remember))
        wrong = {"htm": "POST", "htu": "https://api.example/v1/me"}
        self.assertVerdict(Code.PROOF_MISMATCH, Token.open, access, key, rules(proof=proof, request=wrong, proof_seen_jti=[]))
        self.assertVerdict(Code.PROOF_REPLAYED, Token.open, access, key, rules(proof=proof, request=plain, proof_seen_jti=["p-1"]))
        stale = Rules(issuer="https://issuer.example", audience="api", now=NOW + 100, proof=proof, request=plain, proof_seen_jti=[])
        self.assertVerdict(Code.PROOF_EXPIRED, Token.open, access, key, stale)
        claims = Token.open(access, key, rules(ignore_cnf=True))
        self.assertEqual(claims["cnf"], self.spk.to_paserk())

    def test_normalize_target(self):
        self.assertEqual(Holder.normalize_target("HTTPS://API.Example:443/a?b#c"), "https://api.example/a")
        self.assertVerdict(Code.ARGUMENT, Holder.normalize_target, "nope")

    def test_secret_key_id(self):
        self.sk.key_id = "client-1"
        self.assertEqual(self.sk.key_id, "client-1")
        self.sk.clear_key_id()
        self.assertIsNone(self.sk.key_id)
        self.assertEqual(self.pk.key_id, self.pk.paserk_id())
        self.pk.clear_key_id()
        self.assertIsNone(self.pk.key_id)


@unittest.skipUnless(cb2.has_seal(), "kcb2.seal unavailable in this build")
class SealTest(Verdicts):
    def test_seal_and_unseal(self):
        r = RecipientKey.generate()
        rp = r.public_key()
        rec = rp.to_paserk()
        self.assertEqual(len(rec), 1637)
        self.assertTrue(rec.startswith("kcb2.recipient."))
        secret = r.to_paserk()
        self.assertEqual(len(secret), 65)
        r2 = RecipientKey.from_paserk(secret)
        key = LocalKey.generate()
        sealed = Seal.seal(rp, key)
        self.assertEqual(len(sealed), 1632)
        back = Seal.unseal(sealed, r2)
        self.assertEqual(back.paserk_id(), key.paserk_id())
        other = RecipientKey.generate()
        self.assertVerdict(Code.INVALID, Seal.unseal, sealed, other)
        rid = rp.paserk_id()
        self.assertEqual(rid, r2.paserk_id())
        self.assertTrue(rid.startswith("kcb2.rid."))
        self.assertEqual(cb2.RecipientPublicKey.from_paserk(rec).paserk_id(), rid)


if __name__ == "__main__":
    unittest.main()
