import Cb2
import Foundation
import Observation

/// Issues a cb2.local token for a subject and opens it as a verifier for
/// the `api` audience would, optionally after tampering with it.
@MainActor
@Observable
final class TokenPlayground {
    enum Outcome: Equatable {
        case accepted(String)
        case refused(Cb2Error)
    }

    static let audiences = ["api", "billing"]

    var subject = "user-1"
    var audience = "api"
    var tamper = false
    private(set) var token = ""
    private(set) var outcome: Outcome?

    private let key = Result { () throws(Cb2Error) in try LocalKey.generate() }

    func issueAndOpen() {
        do throws(Cb2Error) {
            let key = try key.get()
            let now = Int64(Date().timeIntervalSince1970)
            let expiry = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: TimeInterval(now + 600)))
            let claims: Claims = [
                "iss": "https://issuer.example", "aud": .string(audience), "sub": .string(subject),
                "exp": .string(expiry),
            ]
            let issued = try Token.seal(claims, key: key)
            token = tamper ? String(issued.dropLast()) + (issued.last == "A" ? "B" : "A") : issued
            let opened = try Token.open(
                token, key: key, rules: Rules(issuer: "https://issuer.example", audience: "api", now: now))
            outcome = .accepted("sub=\(opened["sub"]?.stringValue ?? "") aud=\(opened["aud"]?.stringValue ?? "")")
        } catch {
            outcome = .refused(error)
        }
    }
}
