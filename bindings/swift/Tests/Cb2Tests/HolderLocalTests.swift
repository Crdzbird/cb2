import Cb2
import Foundation
import Testing

@Suite struct HolderLocalTests {
    @Test("a local holder proof is checked against the request") func aLocalHolderProofIsCheckedAgainstTheRequest()
        throws
    {
        let key = try LocalKey.generate()
        let cnf = try LocalKey.generate().toPaserk()
        let access = try Token.seal(Fixtures.bound(to: cnf), key: key)
        #expect(throws: Cb2Error.missingProof) { try Token.open(access, key: key, rules: Fixtures.rules) }

        let proof = try Holder.proveLocal(
            proofKey: try LocalKey(paserk: cnf), request: Fixtures.request, accessToken: access, jti: "p-1",
            now: Fixtures.now)
        #expect(proof.hasPrefix("cb2.holder-local."))
        #expect(proof.utf8.count < 450)

        let presented = HolderRequest(htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1")
        var rules = Fixtures.rules(proof: proof, request: presented)
        #expect(throws: Cb2Error.rulesIncomplete) { try Token.open(access, key: key, rules: rules) }
        rules.proofReplay = { _ in true }
        _ = try Token.open(access, key: key, rules: rules)

        let replayed = Fixtures.rules(proof: proof, request: Fixtures.request, seen: ["p-1"])
        #expect(throws: Cb2Error.proofReplayed) { try Token.open(access, key: key, rules: replayed) }

        let post = HolderRequest(htm: "POST", htu: "https://api.example/v1/me")
        let mismatch = Fixtures.rules(proof: proof, request: post, seen: [])
        #expect(throws: Cb2Error.proofMismatch) { try Token.open(access, key: key, rules: mismatch) }

        let forgedProof = try Holder.proveLocal(
            proofKey: try LocalKey.generate(), request: Fixtures.request, accessToken: access, jti: "p-2",
            now: Fixtures.now)
        let forged = Fixtures.rules(proof: forgedProof, request: Fixtures.request, seen: [])
        #expect(throws: Cb2Error.proofInvalid) { try Token.open(access, key: key, rules: forged) }
    }
}
