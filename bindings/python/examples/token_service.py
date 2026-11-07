"""A token service on the standard library's http.server, and a client that drives it.

The service issues cb2.local and cb2.public access tokens, and compact
cb3.local ones, and serves one protected resource, GET /me, which opens or verifies the token under
fixed rules and, for a token bound to a client key, checks the holder
proof sent with the request.

    python token_service.py            run the demo: start the service, drive it, stop
    python token_service.py serve      keep the service running on 127.0.0.1:8080

Endpoints:

    POST /token/local    {"sub": ...}             a cb2.local access token
    POST /token/public   {"sub": ...}             a cb2.public access token
    POST /token/compact  {"sub": ...}             a compact cb3.local access token
    POST /token/bound    {"sub": ..., "cnf": ...} a cb2.local token bound to the client's
                                                  kcb2.public key, or without cnf to a
                                                  kcb2.local proof key returned with it
    GET  /me             Authorization: CB2 <token>, CB2-Proof: <proof> when bound

A refusal is a 401 with the verdict name, for example {"error": "expired"}.
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

import cb2
from cb2 import Cb2Error, Compact, Holder, LocalKey, PublicKey, Rules, SecretKey, Token

ISSUER = "https://issuer.example"
AUDIENCE = "api"
LIFETIME = datetime.timedelta(minutes=5)


class ReplayStore:
    """Remembers proof ids so that each holder proof is accepted once."""

    def __init__(self) -> None:
        self._seen: set[str] = set()
        self._lock = threading.Lock()

    def first_time(self, jti: str) -> bool:
        """True the first time jti is seen, False after that."""
        with self._lock:
            if jti in self._seen:
                return False
            self._seen.add(jti)
            return True


class Issuer:
    """The keys of the service and the claims of the tokens it issues."""

    def __init__(self) -> None:
        self.local_key = LocalKey.generate()
        self.secret_key = SecretKey.generate() if cb2.has_public() else None
        self.public_key = self.secret_key.public_key() if self.secret_key else None
        self.proofs = ReplayStore()

    def claims(self, sub: str, cnf: str | None = None) -> dict[str, Any]:
        """Claims for sub, valid from now for LIFETIME, bound to cnf when given."""
        now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": sub,
            "iat": now.isoformat(),
            "exp": (now + LIFETIME).isoformat(),
            "jti": str(uuid.uuid4()),
        }
        if cnf is not None:
            claims["cnf"] = cnf
        return claims

    def check(self, token: str, proof: str | None, htm: str, htu: str) -> dict[str, Any]:
        """Opens or verifies token under the service's rules; raises Cb2Error on a refusal."""
        rules = Rules(issuer=ISSUER, audience=AUDIENCE)
        if proof is not None:
            request = {"htm": htm, "htu": htu}
            rules = Rules(
                issuer=ISSUER, audience=AUDIENCE, proof=proof, request=request, proof_replay=self.proofs.first_time
            )
        if token.startswith("cb3.local."):
            return Compact.open(token, self.local_key, rules)
        if token.startswith("cb2.public.") and self.public_key is not None:
            return Token.verify(token, self.public_key, rules)
        return Token.open(token, self.local_key, rules)


def handler_for(issuer: Issuer) -> type[BaseHTTPRequestHandler]:
    """A request handler class serving the endpoints for issuer."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def reply(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            sub = str(body.get("sub", "anonymous"))
            route = urlsplit(self.path).path
            if route == "/token/local":
                self.reply(200, {"token": Token.seal(issuer.local_key, issuer.claims(sub))})
                return
            if route == "/token/compact":
                self.reply(200, {"token": Compact.seal(issuer.local_key, issuer.claims(sub))})
                return
            if route == "/token/public":
                if issuer.secret_key is None:
                    self.reply(503, {"error": "unavailable"})
                    return
                self.reply(200, {"token": Token.sign(issuer.secret_key, issuer.claims(sub))})
                return
            if route == "/token/bound":
                cnf = body.get("cnf")
                if cnf is not None:
                    self.reply(200, {"token": Token.seal(issuer.local_key, issuer.claims(sub, str(cnf)))})
                    return
                proof_key = LocalKey.generate().to_paserk()
                token = Token.seal(issuer.local_key, issuer.claims(sub, proof_key))
                self.reply(200, {"token": token, "proof_key": proof_key})
                return
            self.reply(404, {"error": "not_found"})

        def do_GET(self) -> None:
            if urlsplit(self.path).path != "/me":
                self.reply(404, {"error": "not_found"})
                return
            scheme, _, token = self.headers.get("Authorization", "").partition(" ")
            if scheme != "CB2" or not token:
                self.reply(401, {"error": "missing_token"})
                return
            htu = f"http://{self.headers.get('Host', '')}{self.path}"
            try:
                claims = issuer.check(token, self.headers.get("CB2-Proof"), "GET", htu)
            except Cb2Error as e:
                self.reply(401, {"error": e.name, "code": e.code})
                return
            self.reply(200, {"sub": claims["sub"], "claims": claims})

    return Handler


class Client:
    """A client of the service over urllib."""

    def __init__(self, base: str) -> None:
        self.base = base

    def call(
        self, method: str, path: str, body: Any = None, headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, Any]]:
        """Sends one request and returns (status, JSON body)."""
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                reply: dict[str, Any] = json.loads(response.read())
                return response.status, reply
        except urllib.error.HTTPError as e:
            refused: dict[str, Any] = json.loads(e.read())
            return e.code, refused

    def token(self, kind: str, body: dict[str, Any]) -> dict[str, Any]:
        """Asks for an access token of kind (local, compact, public or bound)."""
        status, reply = self.call("POST", f"/token/{kind}", body)
        if status != 200:
            raise RuntimeError(f"/token/{kind} answered {status}: {reply}")
        return reply

    def me(self, token: str, proof: str | None = None) -> tuple[int, dict[str, Any]]:
        """GET /me with the token and, when given, a holder proof."""
        headers = {"Authorization": f"CB2 {token}"}
        if proof is not None:
            headers["CB2-Proof"] = proof
        return self.call("GET", "/me", headers=headers)


def tampered(token: str) -> str:
    """The token with its last character changed."""
    return token[:-1] + ("B" if token[-1] == "A" else "A")


class Demo:
    """Drives the service and checks every answer against the expected one."""

    def __init__(self, client: Client) -> None:
        self.client = client
        self.failures = 0

    def expect(self, label: str, status: int, reply: dict[str, Any], want: int, error: str | None = None) -> None:
        """Prints one step and counts it as a failure when the answer is not the expected one."""
        ok = status == want and (error is None or reply.get("error") == error)
        shown = reply.get("error") or f"sub={reply.get('sub')}"
        print(f"{'ok  ' if ok else 'FAIL'} {label}: {status} {shown}")
        if not ok:
            self.failures += 1

    def run(self) -> int:
        """Runs every step; returns the number of failures."""
        local = self.client.token("local", {"sub": "alice"})["token"]
        self.expect("cb2.local token opens", *self.client.me(local), 200)
        self.expect("tampered cb2.local token is refused", *self.client.me(tampered(local)), 401, "invalid")
        self.expect("request without a token is refused", *self.client.call("GET", "/me"), 401, "missing_token")
        compact = self.client.token("compact", {"sub": "dave"})["token"]
        self.expect(f"compact token opens, {len(compact)} chars against {len(local)}", *self.client.me(compact), 200)
        self.expect("tampered compact token is refused", *self.client.me(tampered(compact)), 401, "invalid")
        self.public_steps()
        self.holder_steps()
        return self.failures

    def public_steps(self) -> None:
        """cb2.public: a signed token verifies; a token signed by another pair is refused."""
        if not cb2.has_public():
            print("skip cb2.public: this build has no liboqs")
            return
        signed = self.client.token("public", {"sub": "bob"})["token"]
        self.expect("cb2.public token verifies", *self.client.me(signed), 200)
        forged = Token.sign(
            SecretKey.generate(), {"iss": ISSUER, "aud": AUDIENCE, "sub": "mallory", "exp": "2099-01-01T00:00:00+00:00"}
        )
        self.expect("cb2.public token from another key is refused", *self.client.me(forged), 401, "invalid")

    def holder_steps(self) -> None:
        """A token bound to a client key needs a fresh proof for each request."""
        url = self.client.base + "/me"
        if cb2.has_public():
            client_key = SecretKey.generate()
            public: PublicKey = client_key.public_key()
            access = self.client.token("bound", {"sub": "carol", "cnf": public.to_paserk()})["token"]
            mode = "public"

            def prove(target: str, jti: str) -> str:
                return Holder.prove(client_key, "GET", target, access, jti, int(time.time()))

        else:
            reply = self.client.token("bound", {"sub": "carol"})
            access = reply["token"]
            proof_key = LocalKey.from_paserk(reply["proof_key"])
            mode = "local"

            def prove(target: str, jti: str) -> str:
                return Holder.prove_local(proof_key, "GET", target, access, jti, int(time.time()))

        self.holder_checks(mode, access, url, prove)

    def holder_checks(self, mode: str, access: str, url: str, prove: Callable[[str, str], str]) -> None:
        """The holder proof steps, the same for both modes."""
        self.expect(f"bound token without a proof is refused ({mode})", *self.client.me(access), 401, "missing_proof")
        proof = prove(url, str(uuid.uuid4()))
        self.expect(f"bound token with its proof opens ({mode})", *self.client.me(access, proof), 200)
        self.expect(f"the same proof again is refused ({mode})", *self.client.me(access, proof), 401, "proof_replayed")
        elsewhere = prove(url.replace("/me", "/admin"), str(uuid.uuid4()))
        self.expect(
            f"a proof for another target is refused ({mode})", *self.client.me(access, elsewhere), 401, "proof_mismatch"
        )


def serve(host: str, port: int) -> ThreadingHTTPServer:
    """A server for a fresh Issuer, bound but not yet serving."""
    return ThreadingHTTPServer((host, port), handler_for(Issuer()))


def main(argv: list[str] | None = None) -> int:
    """Runs the demo, or with serve keeps the service running."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("command", nargs="?", choices=["demo", "serve"], default="demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args(argv)
    print(f"cb2 {cb2.version()} from {cb2.library_path()}")
    if args.command == "serve":
        server = serve(args.host, args.port)
        print(f"serving on http://{args.host}:{server.server_address[1]}")
        server.serve_forever()
        return 0
    server = serve(args.host, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        failures = Demo(Client(f"http://{args.host}:{server.server_address[1]}")).run()
    finally:
        server.shutdown()
        server.server_close()
    print("all steps behaved as expected" if failures == 0 else f"{failures} step(s) did not behave as expected")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
