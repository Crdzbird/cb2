import Cb2
import Foundation
import Testing

@Suite(.enabled(if: Library.hasPublic, "cb2.public is not in this build"))
struct CompactPublicTests {
    @Test("compact public tokens sign and verify") func compactPublicTokensSignAndVerify() throws {
        let secret = try SecretKey.generate()
        let pub = try secret.publicKey()
        let compact = try Compact.sign(Fixtures.claims, key: secret)
        let full = try Token.sign(Fixtures.claims, key: secret)
        #expect(compact.hasPrefix("cb3.public."))
        #expect(compact.utf8.count < full.utf8.count)
        #expect(try Compact.verify(compact, key: pub, rules: Fixtures.rules)["sub"] == "user-1")

        #expect(throws: Cb2Error.invalid) { try Token.verify(compact, key: pub, rules: Fixtures.rules) }
        #expect(throws: Cb2Error.invalid) { try Compact.verify(full, key: pub, rules: Fixtures.rules) }
        let stranger = try SecretKey.generate().publicKey()
        #expect(throws: Cb2Error.invalid) { try Compact.verify(compact, key: stranger, rules: Fixtures.rules) }
        var other = Fixtures.rules
        other.audience = "web"
        #expect(throws: Cb2Error.audienceMismatch) { try Compact.verify(compact, key: pub, rules: other) }

        let peeked = try #require(try Compact.peekKeyDigest(compact))
        #expect(peeked == (try Compact.keyDigest(try #require(secret.keyId))))

        let cnf = try LocalKey.generate().toPaserk()
        #expect(throws: Cb2Error.argument) { try Compact.sign(Fixtures.bound(to: cnf), key: secret) }
    }

    @Test("compact public tokens sign and verify under a claim table")
    func compactPublicTokensSignAndVerifyUnderAClaimTable() throws {
        let secret = try SecretKey.generate()
        let pub = try secret.publicKey()
        let entries = ["https://issuer.example", "api", "billing"]
        let token = try Compact.sign(Fixtures.claims, key: secret, table: try ClaimTable(entries))
        #expect(token.hasPrefix("cb3.public."))
        let verified = try Compact.verify(token, key: pub, table: try ClaimTable(entries), rules: Fixtures.rules)
        #expect(verified["aud"] == "api")
        #expect(throws: Cb2Error.invalid) { try Compact.verify(token, key: pub, rules: Fixtures.rules) }
        let reordered = try ClaimTable(["api", "https://issuer.example", "billing"])
        #expect(throws: Cb2Error.invalid) {
            try Compact.verify(token, key: pub, table: reordered, rules: Fixtures.rules)
        }
    }
}
