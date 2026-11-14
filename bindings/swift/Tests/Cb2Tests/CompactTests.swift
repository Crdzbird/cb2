import Cb2
import Foundation
import Testing

@Suite struct CompactTests {
    @Test("a compact token is shorter and opens to the same claims")
    func aCompactTokenIsShorterAndOpensToTheSameClaims() throws {
        let key = try LocalKey.generate()
        let compact = try Compact.seal(Fixtures.claims, key: key)
        let full = try Token.seal(Fixtures.claims, key: key)
        #expect(compact.hasPrefix("cb3.local."))
        #expect(compact.utf8.count < full.utf8.count)
        let opened = try Compact.open(compact, key: key, rules: Fixtures.rules)
        #expect(opened == (try Token.open(full, key: key, rules: Fixtures.rules)))
        #expect(opened["role"] == "admin")

        #expect(throws: Cb2Error.invalid) { try Token.open(compact, key: key, rules: Fixtures.rules) }
        #expect(throws: Cb2Error.invalid) { try Compact.open(full, key: key, rules: Fixtures.rules) }
        #expect(throws: Cb2Error.invalid) {
            try Compact.open(compact, key: key, rules: Fixtures.rules, implicit: Data("x".utf8))
        }
    }

    @Test("a compact token gives the verdicts of the rules") func aCompactTokenGivesTheVerdictsOfTheRules() throws {
        let key = try LocalKey.generate()
        let token = try Compact.seal(Fixtures.claims, key: key)
        #expect(throws: Cb2Error.rulesIncomplete) { try Compact.open(token, key: key) }
        var other = Fixtures.rules
        other.audience = "web"
        #expect(throws: Cb2Error.audienceMismatch) { try Compact.open(token, key: key, rules: other) }
        var late = Fixtures.rules
        late.now = 4_102_444_800
        #expect(throws: Cb2Error.expired) { try Compact.open(token, key: key, rules: late) }
        var seen = Fixtures.rules
        seen.seenJti = ["id-1"]
        #expect(throws: Cb2Error.replayed) { try Compact.open(token, key: key, rules: seen) }

        let store = SeenStore()
        var checked = Fixtures.rules
        checked.replay = { store.accept($0) }
        _ = try Compact.open(token, key: key, rules: checked)
        #expect(store.ids == ["id-1"])
        #expect(throws: Cb2Error.replayed) { try Compact.open(token, key: key, rules: checked) }
    }

    @Test("the peeked key digest is the digest of the key id") func thePeekedKeyDigestIsTheDigestOfTheKeyId() throws {
        let key = try LocalKey.generate()
        let token = try Compact.seal(Fixtures.claims, key: key)
        let peeked = try #require(try Compact.peekKeyDigest(token))
        #expect(peeked.count == Compact.keyDigestBytes)
        #expect(peeked == (try Compact.keyDigest(try #require(key.keyId))))
        #expect(peeked != (try Compact.keyDigest("rotation-1")))
        #expect(try Compact.peekKeyDigest(Token.seal(Fixtures.claims, key: key)) == nil)
        #expect(throws: Cb2Error.argument) { try Compact.keyDigest("a\nb") }
        #expect(try Compact.keyDigest("").count == Compact.keyDigestBytes)

        let bare = try key.withoutKeyId()
        let unnamed = try Compact.seal(Fixtures.claims, key: bare)
        #expect(try Compact.peekKeyDigest(unnamed) == nil)
        #expect(throws: Cb2Error.invalid) { try Compact.open(token, key: bare, rules: Fixtures.rules) }
        #expect(try Compact.open(unnamed, key: bare, rules: Fixtures.rules)["sub"] == "user-1")
    }

    @Test("the compact issuer refuses a fraction cb2 accepts")
    func theCompactIssuerRefusesAFractionCb2Accepts() throws {
        let key = try LocalKey.generate()
        let fraction: Claims = [
            "iss": "https://issuer.example", "aud": "api", "exp": "2099-01-01T00:00:00+00:00", "n": 1.5,
        ]
        #expect(throws: Cb2Error.argument) { try Compact.seal(fraction, key: key) }
        #expect(try Token.seal(fraction, key: key).hasPrefix("cb2.local."))
        var whole = fraction
        whole["n"] = -9_007_199_254_740_993
        let opened = try Compact.open(Compact.seal(whole, key: key), key: key, rules: Fixtures.rules)
        #expect(opened["n"]?.integerValue == -9_007_199_254_740_993)
    }

    @Test("a compact access token is bound to a local proof key")
    func aCompactAccessTokenIsBoundToALocalProofKey() throws {
        let key = try LocalKey.generate()
        let cnf = try LocalKey.generate().toPaserk()
        let access = try Compact.seal(Fixtures.bound(to: cnf), key: key)
        #expect(throws: Cb2Error.missingProof) { try Compact.open(access, key: key, rules: Fixtures.rules) }

        let proof = try Holder.proveLocal(
            proofKey: try LocalKey(paserk: cnf), request: Fixtures.request, accessToken: access, jti: "p-1",
            now: Fixtures.now)
        var rules = Fixtures.rules(proof: proof, request: Fixtures.request)
        rules.proofReplay = { _ in true }
        #expect(try Compact.open(access, key: key, rules: rules)["cnf"]?.stringValue == cnf)

        let post = HolderRequest(htm: "POST", htu: "https://api.example/v1/me")
        let mismatch = Fixtures.rules(proof: proof, request: post, seen: [])
        #expect(throws: Cb2Error.proofMismatch) { try Compact.open(access, key: key, rules: mismatch) }
    }
}
