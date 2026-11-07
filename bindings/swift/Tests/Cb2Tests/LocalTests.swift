import Cb2
import Foundation
import Testing

@Suite struct LocalTests {
    @Test("local keys serialize and carry a key id") func localKeysSerializeAndCarryAKeyId() throws {
        let key = try LocalKey.generate()
        let paserk = try key.toPaserk()
        #expect(paserk.hasPrefix("kcb2.local."))
        #expect(paserk.count == 54)
        let id = try key.paserkId
        #expect(id.hasPrefix("kcb2.lid."))
        #expect(key.keyId == id)
        #expect(try LocalKey(paserk: paserk).paserkId == id)

        let rotated = try key.withKeyId("rotation-1")
        #expect(rotated.keyId == "rotation-1")
        #expect(key.keyId == id)
        #expect(try rotated.paserkId == id)
        #expect(throws: Cb2Error.argument) { try key.withKeyId("a\u{200B}") }
        #expect(try rotated.withoutKeyId().keyId == nil)

        #expect(throws: Cb2Error.argument) { try LocalKey(bytes: Data(repeating: 7, count: 32)) }
    }

    @Test("raw local tokens round trip and refuse tampering") func rawLocalTokensRoundTripAndRefuseTampering() throws {
        let key = try LocalKey.generate()
        let same = try LocalKey(paserk: try key.toPaserk())
        let message = Data("hello".utf8)
        let footer = Data("{\"kid\":\"x\"}".utf8)
        let token = try Local.seal(message, key: key, footer: footer)
        #expect(token.hasPrefix("cb2.local."))
        #expect(try Local.open(token, key: same, footer: footer) == message)
        #expect(throws: Cb2Error.invalid) { try Local.open(token, key: same) }
        let tampered = String(token.dropLast()) + (token.last == "A" ? "B" : "A")
        #expect(throws: Cb2Error.invalid) { try Local.open(tampered, key: same, footer: footer) }
    }

    @Test("claims tokens open under the rules and report every verdict")
    func claimsTokensOpenUnderTheRulesAndReportEveryVerdict() throws {
        let key = try LocalKey.generate()
        let token = try Token.seal(Fixtures.claims, key: key)
        let opened = try Token.open(token, key: key, rules: Fixtures.rules)
        #expect(opened["role"] == "admin")
        #expect(opened["jti"] == "id-1")
        #expect(try Token.peekKeyId(token) == key.paserkId)

        #expect(throws: Cb2Error.rulesIncomplete) { try Token.open(token, key: key) }
        var other = Fixtures.rules
        other.audience = "other"
        #expect(throws: Cb2Error.audienceMismatch) { try Token.open(token, key: key, rules: other) }
        var late = Fixtures.rules
        late.now = 4_102_444_801
        #expect(throws: Cb2Error.expired) { try Token.open(token, key: key, rules: late) }
        var lifetime = Fixtures.rules
        lifetime.maxLifetime = 60
        #expect(throws: Cb2Error.lifetimeExceeded) { try Token.open(token, key: key, rules: lifetime) }
        var seen = Fixtures.rules
        seen.seenJti = ["id-1"]
        #expect(throws: Cb2Error.replayed) { try Token.open(token, key: key, rules: seen) }

        let zeroWidth: Claims = ["sub": "a\u{200B}b", "exp": "2099-01-01T00:00:00+00:00"]
        #expect(throws: Cb2Error.argument) { try Token.seal(zeroWidth, key: key) }
    }

    @Test("the replay closure accepts once and a thrown error refuses")
    func theReplayClosureAcceptsOnceAndAThrownErrorRefuses() throws {
        let key = try LocalKey.generate()
        let token = try Token.seal(Fixtures.claims, key: key)
        let store = SeenStore()
        var rules = Fixtures.rules
        rules.replay = { store.accept($0) }
        _ = try Token.open(token, key: key, rules: rules)
        #expect(store.ids == ["id-1"])
        #expect(throws: Cb2Error.replayed) { try Token.open(token, key: key, rules: rules) }

        struct StoreDown: Error {}
        var failing = Fixtures.rules
        failing.replay = { _ in throw StoreDown() }
        #expect(throws: Cb2Error.replayed) { try Token.open(token, key: key, rules: failing) }
    }

    @Test("every claim value kind survives a seal and an open") func everyClaimValueKindSurvives() throws {
        let key = try LocalKey.generate()
        var claims = Fixtures.claims
        claims["text"] = "quote \" backslash \\ tab \t newline \n bell \u{07} accent \u{E9} kana \u{30AB}"
        claims["count"] = 9_007_199_254_740_993
        claims["negative"] = -42
        claims["ratio"] = 0.25
        claims["flag"] = false
        claims["nothing"] = nil
        claims["list"] = ["a", 1, true, nil, ["nested": 2.5]]
        claims["object"] = ["inner": ["deep": "value"], "empty": [:], "none": []]
        let opened = try Token.open(Token.seal(claims, key: key), key: key, rules: Fixtures.rules)
        #expect(opened == claims)
        #expect(throws: Cb2Error.argument) {
            try Token.seal(["exp": "2099-01-01T00:00:00+00:00", "x": .number(.nan)], key: key)
        }
    }

    @Test("a typed catch matches the verdict") func typedCatchMatchesTheVerdict() throws {
        let key = try LocalKey.generate()
        let token = try Token.seal(Fixtures.claims, key: key)
        var late = Fixtures.rules
        late.now = 4_102_444_801
        var caught = ""
        do throws(Cb2Error) {
            _ = try Token.open(token, key: key, rules: late)
        } catch .expired {
            caught = "expired"
        } catch {
            caught = error.name
        }
        #expect(caught == "expired")
    }

    @Test("local keys wrap under another local key") func localKeysWrapUnderAnotherLocalKey() throws {
        let key = try LocalKey.generate()
        let wrapping = try LocalKey.generate()
        let wrapped = try KeyWrap.wrap(key, with: wrapping)
        #expect(wrapped.hasPrefix("kcb2.local-wrap."))
        #expect(wrapped.count == 144)
        #expect(try KeyWrap.unwrap(wrapped, with: wrapping).paserkId == key.paserkId)
        #expect(throws: Cb2Error.invalid) { try KeyWrap.unwrap(wrapped, with: key) }
    }

    @Test("one key serves concurrent tasks") func oneKeyServesConcurrentTasks() async throws {
        let key = try LocalKey.generate()
        let opened = try await withThrowingTaskGroup(of: String?.self) { group in
            for index in 0..<16 {
                group.addTask {
                    let token = try Token.seal(
                        ["sub": .string("user-\(index)"), "exp": "2099-01-01T00:00:00+00:00"], key: key)
                    var rules = Rules(now: Fixtures.now)
                    rules.allowAnyIssuer = true
                    rules.allowAnyAudience = true
                    return try Token.open(token, key: key, rules: rules)["sub"]?.stringValue
                }
            }
            return try await group.reduce(into: Set<String>()) { $0.insert($1 ?? "") }
        }
        #expect(opened == Set((0..<16).map { "user-\($0)" }))
    }
}
