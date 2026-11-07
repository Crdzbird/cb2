import Cb2
import Foundation
import Testing

@Suite struct LibraryTests {
    @Test("the version is reported") func theVersionIsReported() {
        #expect(!Library.version.isEmpty)
        #expect(Library.abiVersion == 0)
    }

    @Test(
        "codes map to verdicts and names",
        arguments: [
            (Int32(3), Cb2Error.argument, "argument"),
            (9, .expired, "expired"),
            (24, .proofReplayed, "proof_replayed"),
            (0, .unknown(0), "ok"),
            (99, .unknown(99), "unknown"),
        ])
    func codesMapToVerdictsAndNames(code: Int32, verdict: Cb2Error, name: String) {
        #expect(Cb2Error(code: code) == verdict)
        #expect(verdict.code == code)
        #expect(verdict.name == name)
    }

    @Test("every known verdict round trips through its code") func everyKnownVerdictRoundTripsThroughItsCode() {
        for code in Int32(1)...24 {
            let verdict = Cb2Error(code: code)
            #expect(verdict != .unknown(code))
            #expect(verdict.code == code)
        }
        #expect(Cb2Error.expired.description == "cb2 error 9 (expired)")
    }

    @Test("claim values round trip through JSON") func claimValuesRoundTripThroughJson() throws {
        let claims: Claims = [
            "s": "text", "i": 42, "d": 1.5, "b": true, "n": nil, "a": ["x", 1], "o": ["k": false],
        ]
        let data = try JSONEncoder().encode(claims)
        #expect(try JSONDecoder().decode(Claims.self, from: data) == claims)
        #expect(claims["i"]?.integerValue == 42)
        #expect(claims["i"]?.doubleValue == 42)
        #expect(claims["s"]?.stringValue == "text")
        #expect(claims["b"]?.boolValue == true)
        #expect(claims["a"]?.arrayValue?.count == 2)
        #expect(claims["o"]?.objectValue?["k"] == false)
        #expect(claims["s"]?.integerValue == nil)
    }
}
