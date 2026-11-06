import Cb2
import Foundation
import XCTest

/// The Swift bridge exercised the way bindings/c/test/test_c.c exercises
/// the C ABI: keys, raw tokens, claims tokens with rules and both replay
/// callbacks, holder proofs of both modes, key wrapping and sealing, and every verdict.
final class Cb2Tests: XCTestCase {
    let claims: [String: Any] = [
        "iss": "https://issuer.example",
        "sub": "user-1",
        "aud": "api",
        "exp": "2099-01-01T00:00:00+00:00",
        "jti": "id-1",
        "role": "admin",
    ]

    var rules: Rules {
        var r = Rules()
        r.issuer = "https://issuer.example"
        r.audience = "api"
        r.now = 1_700_000_000
        return r
    }

    /// The verdict of a call as the library names it, "ok" when it succeeded.
    func verdict(_ body: () throws -> Any) -> String {
        do {
            _ = try body()
            return "ok"
        } catch let error as Cb2Error {
            return error.name
        } catch {
            return "\(error)"
        }
    }

    func testLibrary() {
        XCTAssertFalse(Cb2.version().isEmpty)
        XCTAssertEqual(Cb2Error(code: 3).name, "argument")
        XCTAssertEqual(Cb2Error(code: 0).name, "ok")
        XCTAssertEqual(Cb2Error(.proofReplayed).name, "proof_replayed")
        XCTAssertEqual(Cb2Error(code: 99).name, "unknown")
        XCTAssertNil(Cb2Error(code: 99).kind)
        XCTAssertEqual(Cb2Error(code: 9).kind, .expired)
    }

    func testLocalKeys() throws {
        let k = try LocalKey.generate()
        let paserk = try k.toPaserk()
        XCTAssertTrue(paserk.hasPrefix("kcb2.local."))
        XCTAssertEqual(paserk.count, 54)
        let id = try k.paserkId
        XCTAssertTrue(id.hasPrefix("kcb2.lid."))
        XCTAssertEqual(k.keyId, id)
        let same = try LocalKey(paserk: paserk)
        XCTAssertEqual(try same.paserkId, id)

        try k.setKeyId("rotation-1")
        XCTAssertEqual(k.keyId, "rotation-1")
        XCTAssertEqual(verdict { try k.setKeyId("a\u{200B}") }, "argument")
        k.clearKeyId()
        XCTAssertNil(k.keyId)

        let weak = Data(repeating: 7, count: 32)
        XCTAssertEqual(verdict { try LocalKey(bytes: weak) }, "argument")
    }

    func testLocalRoundTrip() throws {
        let k = try LocalKey.generate()
        let same = try LocalKey(paserk: try k.toPaserk())
        let message = Data("hello".utf8)
        let footer = Data("{\"kid\":\"x\"}".utf8)
        let token = try Local.seal(key: k, message: message, footer: footer)
        XCTAssertTrue(token.hasPrefix("cb2.local."))
        XCTAssertEqual(try Local.open(token: token, key: same, footer: footer), message)
        XCTAssertEqual(verdict { try Local.open(token: token, key: same) }, "invalid")
        let last = token.last == "A" ? "B" : "A"
        let tampered = String(token.dropLast()) + last
        XCTAssertEqual(verdict { try Local.open(token: tampered, key: same, footer: footer) }, "invalid")
    }

    func testClaimsVerdicts() throws {
        let k = try LocalKey.generate()
        let token = try Token.seal(key: k, claims: claims)
        let opened = try Token.open(token: token, key: k, rules: rules)
        XCTAssertEqual(opened["role"] as? String, "admin")
        XCTAssertEqual(opened["jti"] as? String, "id-1")
        XCTAssertEqual(try Token.peekKeyId(token: token), try k.paserkId)

        XCTAssertEqual(verdict { try Token.open(token: token, key: k) }, "rules_incomplete")
        var other = rules
        other.audience = "other"
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: other) }, "audience_mismatch")
        var late = rules
        late.now = 4_102_444_801
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: late) }, "expired")
        var lifetime = rules
        lifetime.maxLifetime = 60
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: lifetime) }, "lifetime_exceeded")
        var seen = rules
        seen.seenJti = ["id-1"]
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: seen) }, "replayed")

        let zeroWidth: [String: Any] = ["sub": "a\u{200B}b", "exp": "2099-01-01T00:00:00+00:00"]
        XCTAssertEqual(verdict { try Token.seal(key: k, claims: zeroWidth) }, "argument")
    }

    func testReplayClosure() throws {
        let k = try LocalKey.generate()
        let token = try Token.seal(key: k, claims: claims)
        var remembered: [String] = []
        var replay = rules
        replay.replay = { jti in
            if remembered.contains(jti) {
                return false
            }
            remembered.append(jti)
            return true
        }
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: replay) }, "ok")
        XCTAssertEqual(remembered, ["id-1"])
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: replay) }, "replayed")

        struct StoreDown: Error {}
        var failing = rules
        failing.replay = { _ in throw StoreDown() }
        XCTAssertEqual(verdict { try Token.open(token: token, key: k, rules: failing) }, "replayed")
    }

    func testWrapping() throws {
        let k = try LocalKey.generate()
        let wrapping = try LocalKey.generate()
        let wrapped = try KeyWrap.wrap(k, with: wrapping)
        XCTAssertTrue(wrapped.hasPrefix("kcb2.local-wrap."))
        XCTAssertEqual(wrapped.count, 144)
        let unwrapped = try KeyWrap.unwrap(wrapped, with: wrapping)
        XCTAssertEqual(try unwrapped.paserkId, try k.paserkId)
        XCTAssertEqual(verdict { try KeyWrap.unwrap(wrapped, with: k) }, "invalid")
    }

    func testPublicSignAndVerify() throws {
        try XCTSkipUnless(hasPublic(), "cb2.public unavailable in this build")
        let sk = try SecretKey.generate()
        let pk = try sk.publicKey()
        let pub = try pk.toPaserk()
        XCTAssertEqual(pub.count, 2658)
        XCTAssertEqual(try sk.paserkId, try pk.paserkId)
        let pk2 = try PublicKey(paserk: pub)
        let token = try Token.sign(key: sk, claims: claims)
        let verified = try Token.verify(token: token, key: pk2, rules: rules)
        XCTAssertEqual(verified["sub"] as? String, "user-1")
        let stranger = try SecretKey.generate()
        let spk = try stranger.publicKey()
        XCTAssertEqual(verdict { try Token.verify(token: token, key: spk, rules: rules) }, "invalid")

        let message = Data("signed bytes".utf8)
        let raw = try Public.sign(key: sk, message: message, implicit: Data("ctx".utf8))
        XCTAssertTrue(raw.hasPrefix("cb2.public."))
        XCTAssertEqual(try Public.verify(token: raw, key: pk, implicit: Data("ctx".utf8)), message)
        XCTAssertEqual(verdict { try Public.verify(token: raw, key: pk) }, "invalid")
    }

    func testHolderProof() throws {
        try XCTSkipUnless(hasPublic(), "cb2.public unavailable in this build")
        let client = try SecretKey.generate()
        let bound: [String: Any] = [
            "iss": "https://issuer.example",
            "aud": "api",
            "exp": "2099-01-01T00:00:00+00:00",
            "cnf": try client.publicKey().toPaserk(),
        ]
        let k = try LocalKey.generate()
        let access = try Token.seal(key: k, claims: bound)
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: rules) }, "missing_proof")

        let proof = try Holder.prove(client: client, htm: "GET", htu: "https://api.example/v1/me",
                                     accessToken: access, jti: "p-1", now: 1_700_000_000, lifetime: 60)
        XCTAssertTrue(proof.hasPrefix("cb2.holder-public."))

        var presented = rules
        presented.proof = proof
        presented.request = Rules.Request(htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1")
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: presented) }, "rules_incomplete")
        presented.proofReplay = { _ in true }
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: presented) }, "ok")

        var mismatch = rules
        mismatch.proof = proof
        mismatch.request = Rules.Request(htm: "POST", htu: "https://api.example/v1/me")
        mismatch.proofSeenJti = []
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: mismatch) }, "proof_mismatch")

        var replayed = rules
        replayed.proof = proof
        replayed.request = Rules.Request(htm: "GET", htu: "https://api.example/v1/me")
        replayed.proofSeenJti = ["p-1"]
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: replayed) }, "proof_replayed")

        var stale = rules
        stale.now = 1_700_000_100
        stale.proof = proof
        stale.request = Rules.Request(htm: "GET", htu: "https://api.example/v1/me")
        stale.proofSeenJti = []
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: stale) }, "proof_expired")

        var ignore = rules
        ignore.ignoreCnf = true
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: ignore) }, "ok")

        XCTAssertEqual(try Holder.normalizeTarget("HTTPS://API.Example:443/a?b#c"), "https://api.example/a")
        XCTAssertEqual(verdict { try Holder.normalizeTarget("nope") }, "argument")
    }

    func testLocalHolderProof() throws {
        let k = try LocalKey.generate()
        let cnf = try LocalKey.generate().toPaserk()
        let bound: [String: Any] = [
            "iss": "https://issuer.example",
            "aud": "api",
            "exp": "2099-01-01T00:00:00+00:00",
            "cnf": cnf,
        ]
        let access = try Token.seal(key: k, claims: bound)
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: rules) }, "missing_proof")

        let proof = try Holder.proveLocal(proofKey: try LocalKey(paserk: cnf), htm: "GET",
                                          htu: "https://api.example/v1/me", accessToken: access, jti: "p-1",
                                          now: 1_700_000_000)
        XCTAssertTrue(proof.hasPrefix("cb2.holder-local."))
        XCTAssertLessThan(proof.utf8.count, 450)

        var presented = rules
        presented.proof = proof
        presented.request = Rules.Request(htm: "GET", htu: "HTTPS://API.EXAMPLE:443/v1/me?x=1")
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: presented) }, "rules_incomplete")
        presented.proofReplay = { _ in true }
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: presented) }, "ok")

        var replayed = rules
        replayed.proof = proof
        replayed.request = Rules.Request(htm: "GET", htu: "https://api.example/v1/me")
        replayed.proofSeenJti = ["p-1"]
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: replayed) }, "proof_replayed")

        var mismatch = replayed
        mismatch.request = Rules.Request(htm: "POST", htu: "https://api.example/v1/me")
        mismatch.proofSeenJti = []
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: mismatch) }, "proof_mismatch")

        var forged = replayed
        forged.proof = try Holder.proveLocal(proofKey: try LocalKey.generate(), htm: "GET",
                                             htu: "https://api.example/v1/me", accessToken: access, jti: "p-2",
                                             now: 1_700_000_000)
        forged.proofSeenJti = []
        XCTAssertEqual(verdict { try Token.open(token: access, key: k, rules: forged) }, "proof_invalid")
    }

    func testSealing() throws {
        try XCTSkipUnless(hasSeal(), "kcb2.seal unavailable in this build")
        let r = try RecipientKey.generate()
        let rp = try r.publicKey()
        let rec = try rp.toPaserk()
        XCTAssertTrue(rec.hasPrefix("kcb2.recipient."))
        XCTAssertEqual(rec.count, 1637)
        let secret = try r.toPaserk()
        XCTAssertEqual(secret.count, 65)
        let r2 = try RecipientKey(paserk: secret)
        let k = try LocalKey.generate()
        let sealed = try Seal.seal(k, to: rp)
        XCTAssertEqual(sealed.count, 1632)
        let back = try Seal.unseal(sealed, by: r2)
        XCTAssertEqual(try back.paserkId, try k.paserkId)
        let other = try RecipientKey.generate()
        XCTAssertEqual(verdict { try Seal.unseal(sealed, by: other) }, "invalid")
        let rid = try rp.paserkId
        XCTAssertEqual(rid, try r2.paserkId)
        XCTAssertTrue(rid.hasPrefix("kcb2.rid."))
        XCTAssertEqual(try RecipientPublicKey(paserk: rec).paserkId, rid)
    }
}
