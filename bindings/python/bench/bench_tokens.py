"""Times cb2 against PyJWT and pyseto on one claims payload.

Every format gets the same claims (iss, sub, aud, exp, iat, jti and one
short custom claim), each in its own time encoding: NumericDate integers
for JWT, RFC 3339 text for PASETO and cb2. Each row times creating a
token and a validating decode of it (signature or tag, exp, issuer and
audience), and reports the token size in bytes. pyperf runs every
benchmark in its own worker processes; the table at the end shows the
median per operation.

    python bench/bench_tokens.py                        full run
    python bench/bench_tokens.py --fast                 quicker, noisier
    python bench/bench_tokens.py --debug-single-value   one value, a smoke test
"""

from __future__ import annotations

import datetime as dt
import json
import platform
import secrets
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from typing import Any

import jwt
import pyperf
import pyseto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

import cb2
from cb2 import LocalKey, Rules, SecretKey, Token

ISSUER = "https://issuer.example"
AUDIENCE = "api"
SUBJECT = "user-1"
JTI = "a3f9c1d27e5b4e08"
LIFETIME = 3600
LIBRARIES = ("cb2", "PyJWT", "pyseto", "cryptography", "pyperf")

TokenText = str | bytes


@dataclass(frozen=True)
class Case:
    """One token format: how to create a token and how to validate one."""

    name: str
    create: Callable[[], TokenText]
    validate: Callable[[TokenText], dict[str, Any]]


def _numeric_claims(now: int) -> dict[str, Any]:
    return {
        "iss": ISSUER,
        "sub": SUBJECT,
        "aud": AUDIENCE,
        "exp": now + LIFETIME,
        "iat": now,
        "jti": JTI,
        "role": "admin",
    }


def _text_claims(now: int) -> dict[str, Any]:
    claims = _numeric_claims(now)
    for name in ("exp", "iat"):
        claims[name] = dt.datetime.fromtimestamp(claims[name], dt.timezone.utc).isoformat()
    return claims


def _jwt_case(name: str, algorithm: str, signing: Any, verifying: Any, claims: dict[str, Any]) -> Case:
    options: Any = {"require": ["iss", "sub", "aud", "exp", "iat", "jti"]}

    def validate(token: TokenText) -> dict[str, Any]:
        decoded: dict[str, Any] = jwt.decode(
            token, verifying, algorithms=[algorithm], audience=AUDIENCE, issuer=ISSUER, options=options
        )
        return decoded

    return Case(name, lambda: jwt.encode(claims, signing, algorithm=algorithm), validate)


def _paseto_case(
    name: str, signing: pyseto.KeyInterface, verifying: pyseto.KeyInterface, claims: dict[str, Any]
) -> Case:
    def validate(token: TokenText) -> dict[str, Any]:
        payload = pyseto.decode(verifying, token, deserializer=json, aud=AUDIENCE).payload
        if not isinstance(payload, dict) or payload.get("iss") != ISSUER:
            raise pyseto.VerifyError("iss verification failed.")
        return payload

    return Case(name, lambda: pyseto.encode(signing, claims), validate)


def _pem(private: ed25519.Ed25519PrivateKey) -> tuple[bytes, bytes]:
    secret = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return secret, public


def cases() -> list[Case]:
    """Every format of the comparison, in the order of the table."""
    now = int(time.time())
    numeric, text = _numeric_claims(now), _text_claims(now)
    rules = Rules(issuer=ISSUER, audience=AUDIENCE)
    local = LocalKey.generate()
    shared = secrets.token_bytes(32)
    paseto_local = pyseto.Key.new(version=4, purpose="local", key=secrets.token_bytes(32))
    found = [
        Case("cb2.local", lambda: Token.seal(local, text), lambda t: Token.open(t, local, rules)),
        _jwt_case("JWT HS256 (PyJWT)", "HS256", shared, shared, numeric),
        _paseto_case("PASETO v4.local (pyseto)", paseto_local, paseto_local, text),
    ]
    if cb2.has_public():
        secret = SecretKey.generate()
        public = secret.public_key()
        found.append(Case("cb2.public", lambda: Token.sign(secret, text), lambda t: Token.verify(t, public, rules)))
    edwards = ed25519.Ed25519PrivateKey.generate()
    nist = ec.generate_private_key(ec.SECP256R1())
    pem_secret, pem_public = _pem(ed25519.Ed25519PrivateKey.generate())
    found += [
        _jwt_case("JWT EdDSA (PyJWT)", "EdDSA", edwards, edwards.public_key(), numeric),
        _jwt_case("JWT ES256 (PyJWT)", "ES256", nist, nist.public_key(), numeric),
        _paseto_case(
            "PASETO v4.public (pyseto)",
            pyseto.Key.new(version=4, purpose="public", key=pem_secret),
            pyseto.Key.new(version=4, purpose="public", key=pem_public),
            text,
        ),
    ]
    for case in found:
        if case.validate(case.create()).get("sub") != SUBJECT:
            raise RuntimeError(f"{case.name} does not round trip")
    return found


def _cpu() -> str:
    if platform.system() == "Darwin":
        brand = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True, text=True, check=False
        )
        return brand.stdout.strip() or platform.machine()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    return platform.processor() or platform.machine()


def _versions() -> str:
    return ", ".join(f"{name} {metadata.version(name)}" for name in LIBRARIES)


def report(rows: list[tuple[str, float, float, int]]) -> str:
    """The results as a Markdown table, under the machine and the versions."""
    lines = [
        f"{dt.date.today().isoformat()}, {_cpu()}, {platform.platform()}, Python {platform.python_version()}",
        f"{_versions()}; libcb2_c {cb2.version()}",
        "",
        "| token | create | validating decode | size |",
        "|---|---:|---:|---:|",
    ]
    lines += [
        f"| {name} | {create * 1e6:.1f} us | {check * 1e6:.1f} us | {size} B |" for name, create, check, size in rows
    ]
    return "\n".join(lines)


def main() -> None:
    """Run every benchmark with pyperf and print the table when this process has all of them."""
    runner = pyperf.Runner()
    rows: list[tuple[str, float, float, int]] = []
    complete = True
    for case in cases():
        token = case.create()
        create = runner.bench_func(f"{case.name} create", case.create)
        check = runner.bench_func(f"{case.name} validate", case.validate, token)
        if create is None or check is None:
            complete = False
            continue
        rows.append((case.name, create.median(), check.median(), len(token)))
    if complete:
        print()
        print(report(rows))


if __name__ == "__main__":
    main()
