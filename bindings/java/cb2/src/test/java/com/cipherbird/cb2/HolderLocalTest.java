package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.NOW;
import static com.cipherbird.cb2.Support.TARGET;
import static com.cipherbird.cb2.Support.bound;
import static com.cipherbird.cb2.Support.expect;
import static com.cipherbird.cb2.Support.rules;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class HolderLocalTest {
    @Test
    void localModeProofs() {
        try (LocalKey k = LocalKey.generate(); LocalKey issued = LocalKey.generate()) {
            String cnf = issued.toPaserk();
            String access = Token.seal(k, bound(cnf));
            expect(Code.MISSING_PROOF, "local-bound token without a proof", () -> Token.open(k, access, rules()));
            try (LocalKey client = LocalKey.fromPaserk(cnf); LocalKey stranger = LocalKey.generate()) {
                String proof = Holder.proveLocal(client, "GET", TARGET, null, access, "p-1", NOW, 60);
                assertTrue(proof.startsWith("cb2.holder-local."), "local proof prefix");
                assertTrue(proof.length() < 450, "local proof size");
                Rules presented = rules().proof(proof).request("GET", "HTTPS://API.EXAMPLE:443/v1/me?x=1");
                expect(Code.RULES_INCOMPLETE, "local proof without a proof replay check",
                        () -> Token.open(k, access, presented));
                Token.open(k, access, presented.proofReplay(jti -> true));
                expect(Code.PROOF_MISMATCH, "local proof for another request", () -> Token.open(k, access,
                        rules().proof(proof).request("POST", TARGET).proofSeenJti()));
                expect(Code.PROOF_REPLAYED, "local proof id already seen", () -> Token.open(k, access,
                        rules().proof(proof).request("GET", TARGET).proofSeenJti("p-1")));
                expect(Code.PROOF_EXPIRED, "local proof too old", () -> Token.open(k, access,
                        rules().now(NOW + 100).proof(proof).request("GET", TARGET).proofSeenJti()));
                String forged = Holder.proveLocal(stranger, "GET", TARGET, null, access, "p-2", NOW, 60);
                expect(Code.PROOF_INVALID, "local proof under another key", () -> Token.open(k, access,
                        rules().proof(forged).request("GET", TARGET).proofSeenJti()));
            }
        }
    }

    @Test
    void serverNonce() {
        try (LocalKey k = LocalKey.generate(); LocalKey client = LocalKey.generate()) {
            String access = Token.seal(k, bound(client.toPaserk()));
            String proof = Holder.proveLocal(client, "GET", TARGET, "n-1", access, "p-1", NOW, 60);
            Token.open(k, access, rules().proof(proof).request("GET", TARGET, "n-1").proofSeenJti());
            expect(Code.PROOF_MISMATCH, "local proof with another nonce", () -> Token.open(k, access,
                    rules().proof(proof).request("GET", TARGET, "n-2").proofSeenJti()));
        }
    }
}
