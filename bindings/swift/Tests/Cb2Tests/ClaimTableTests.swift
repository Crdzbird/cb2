import Cb2
import Foundation
import Testing

@Suite struct ClaimTableTests {
    static let entries = ["https://issuer.example", "api", "billing"]

    @Test("a claim table refuses bad entries and has a stable digest")
    func aClaimTableRefusesBadEntriesAndHasAStableDigest() throws {
        for entries in [[], ["a", "a"], ["a", ""], ["a\nb"], ["a\u{200B}"]] {
            #expect(throws: Cb2Error.argument) { try ClaimTable(entries) }
        }
        #expect(throws: Cb2Error.argument) { try ClaimTable((0...256).map { "entry-\($0)" }) }
        #expect(try ClaimTable((0..<256).map { "entry-\($0)" }).digest.count == ClaimTable.digestBytes)

        let digest = try ClaimTable(Self.entries).digest
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        #expect(hex == "767715f4054718828339b957f45d7bfd52b59bfca9188d0eb68d0389090fef4d")
        #expect(digest == (try ClaimTable(Self.entries).digest))
        #expect(digest != (try ClaimTable(["api", "https://issuer.example", "billing"]).digest))
    }

    @Test("a tabled token is shorter and opens only under the same table")
    func aTabledTokenIsShorterAndOpensOnlyUnderTheSameTable() throws {
        let key = try LocalKey.generate()
        let table = try ClaimTable(Self.entries)
        let same = try ClaimTable(Self.entries)
        let reordered = try ClaimTable(["api", "https://issuer.example", "billing"])
        let tabled = try Compact.seal(Fixtures.claims, key: key, table: table)
        let plain = try Compact.seal(Fixtures.claims, key: key)
        #expect(tabled.hasPrefix("cb3.local."))
        #expect(tabled.utf8.count + 30 < plain.utf8.count)
        let opened = try Compact.open(tabled, key: key, table: same, rules: Fixtures.rules)
        #expect(opened == (try Compact.open(plain, key: key, rules: Fixtures.rules)))
        #expect(opened["iss"] == "https://issuer.example")

        #expect(throws: Cb2Error.invalid) { try Compact.open(tabled, key: key, rules: Fixtures.rules) }
        #expect(throws: Cb2Error.invalid) {
            try Compact.open(tabled, key: key, table: reordered, rules: Fixtures.rules)
        }
        #expect(throws: Cb2Error.invalid) { try Compact.open(plain, key: key, table: table, rules: Fixtures.rules) }
    }

    @Test("the rules keep their meaning under a table") func theRulesKeepTheirMeaningUnderATable() throws {
        let key = try LocalKey.generate()
        let table = try ClaimTable(Self.entries)
        let token = try Compact.seal(Fixtures.claims, key: key, table: table)
        var billing = Fixtures.rules
        billing.audience = "billing"
        #expect(throws: Cb2Error.audienceMismatch) {
            try Compact.open(token, key: key, table: table, rules: billing)
        }
        var other = Fixtures.rules
        other.issuer = "https://other.example"
        #expect(throws: Cb2Error.issuerMismatch) { try Compact.open(token, key: key, table: table, rules: other) }
        var any = Rules(now: Fixtures.now)
        any.allowAnyIssuer = true
        any.allowAnyAudience = true
        #expect(try Compact.open(token, key: key, table: table, rules: any)["aud"] == "api")
    }

    @Test("the table prefix is reserved in the implicit assertion")
    func theTablePrefixIsReservedInTheImplicitAssertion() throws {
        let key = try LocalKey.generate()
        let table = try ClaimTable(Self.entries)
        let reserved = Data("kcb3.table.".utf8)
        let plain = try Compact.seal(Fixtures.claims, key: key)
        #expect(throws: Cb2Error.argument) { try Compact.seal(Fixtures.claims, key: key, implicit: reserved) }
        #expect(throws: Cb2Error.argument) {
            try Compact.open(plain, key: key, rules: Fixtures.rules, implicit: reserved)
        }
        let token = try Compact.seal(Fixtures.claims, key: key, table: table, implicit: reserved)
        #expect(
            try Compact.open(token, key: key, table: table, rules: Fixtures.rules, implicit: reserved)["sub"]
                == "user-1")
    }

    @Test("one table serves concurrent tasks") func oneTableServesConcurrentTasks() async throws {
        let key = try LocalKey.generate()
        let table = try ClaimTable(Self.entries)
        let opened = try await withThrowingTaskGroup(of: String?.self) { group in
            for index in 0..<16 {
                group.addTask {
                    var claims = Fixtures.claims
                    claims["sub"] = .string("user-\(index)")
                    let token = try Compact.seal(claims, key: key, table: table)
                    return try Compact.open(token, key: key, table: table, rules: Fixtures.rules)["sub"]?.stringValue
                }
            }
            return try await group.reduce(into: Set<String>()) { $0.insert($1 ?? "") }
        }
        #expect(opened == Set((0..<16).map { "user-\($0)" }))
    }
}
