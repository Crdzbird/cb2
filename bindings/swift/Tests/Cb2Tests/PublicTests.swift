import Cb2
import Foundation
import Testing

@Suite(.enabled(if: Library.hasPublic, "cb2.public is not in this build"))
struct PublicTests {
    @Test("public tokens sign and verify") func publicTokensSignAndVerify() throws {
        let secret = try SecretKey.generate()
        let pub = try secret.publicKey()
        let paserk = try pub.toPaserk()
        #expect(paserk.count == 2658)
        #expect(try secret.paserkId == pub.paserkId)
        let token = try Token.sign(Fixtures.claims, key: secret)
        let verified = try Token.verify(token, key: try PublicKey(paserk: paserk), rules: Fixtures.rules)
        #expect(verified["sub"] == "user-1")
        let stranger = try SecretKey.generate().publicKey()
        #expect(throws: Cb2Error.invalid) { try Token.verify(token, key: stranger, rules: Fixtures.rules) }

        let message = Data("signed bytes".utf8)
        let raw = try Public.sign(message, key: secret, implicit: Data("ctx".utf8))
        #expect(raw.hasPrefix("cb2.public."))
        #expect(try Public.verify(raw, key: pub, implicit: Data("ctx".utf8)) == message)
        #expect(throws: Cb2Error.invalid) { try Public.verify(raw, key: pub) }

        let rotated = try secret.withKeyId("signer-2")
        #expect(rotated.keyId == "signer-2")
        #expect(try Token.peekKeyId(Token.sign(Fixtures.claims, key: rotated)) == "signer-2")
        #expect(try pub.withKeyId("signer-2").keyId == "signer-2")
        #expect(try pub.withoutKeyId().keyId == nil)
    }

    @Test("a public holder proof is checked against the request") func aPublicHolderProofIsCheckedAgainstTheRequest()
        throws
    {
        let client = try SecretKey.generate()
        let key = try LocalKey.generate()
        let access = try Token.seal(Fixtures.bound(to: try client.publicKey().toPaserk()), key: key)
        #expect(throws: Cb2Error.missingProof) { try Token.open(access, key: key, rules: Fixtures.rules) }

        let proof = try Holder.prove(
            client: client, request: Fixtures.request, accessToken: access, jti: "p-1", now: Fixtures.now)
        #expect(proof.hasPrefix("cb2.holder-public."))

        let presented = HolderRequest(htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1")
        var rules = Fixtures.rules(proof: proof, request: presented)
        #expect(throws: Cb2Error.rulesIncomplete) { try Token.open(access, key: key, rules: rules) }
        rules.proofReplay = { _ in true }
        _ = try Token.open(access, key: key, rules: rules)

        let post = HolderRequest(htm: "POST", htu: "https://api.example/v1/me")
        let mismatch = Fixtures.rules(proof: proof, request: post, seen: [])
        #expect(throws: Cb2Error.proofMismatch) { try Token.open(access, key: key, rules: mismatch) }
        let replayed = Fixtures.rules(proof: proof, request: Fixtures.request, seen: ["p-1"])
        #expect(throws: Cb2Error.proofReplayed) { try Token.open(access, key: key, rules: replayed) }
        var stale = Fixtures.rules(proof: proof, request: Fixtures.request, seen: [])
        stale.now = Fixtures.now + 100
        #expect(throws: Cb2Error.proofExpired) { try Token.open(access, key: key, rules: stale) }

        var ignore = Fixtures.rules
        ignore.ignoreCnf = true
        _ = try Token.open(access, key: key, rules: ignore)

        #expect(try Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c") == "https://api.example/a")
        #expect(throws: Cb2Error.argument) { try Holder.normalizeTarget("nope") }
    }
}
