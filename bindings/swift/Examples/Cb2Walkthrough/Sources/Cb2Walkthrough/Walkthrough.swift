import Cb2
import Foundation

/// Issues, opens and verifies cb2.local and cb2.public tokens, shows the
/// refusals a verifier gives, and checks holder proofs of both modes.
///
/// Every call is synchronous; ``run()`` takes a few milliseconds, most of
/// it ML-DSA-65 signing, so an app calls it off the main actor.
public struct Walkthrough: Sendable {
    let now: Int64
    let issuer = "https://issuer.example"
    let audience = "api"
    let resource = HolderRequest(htm: "GET", htu: "https://api.example/v1/me")

    /// A walkthrough whose clock reads `now`.
    public init(now: Date = Date()) {
        self.now = Int64(now.timeIntervalSince1970)
    }

    /// Runs every step; a setup failure ends the run with a failed step.
    public func run() -> [Step] {
        var log = StepLog()
        do throws(Cb2Error) {
            try local(&log)
            try holderLocal(&log)
            if Library.hasPublic {
                try publicTokens(&log)
            }
            if Library.hasSeal {
                try sealing(&log)
            }
        } catch {
            log.record("setup", "Setup", detail: error.description, verdict: error.name, expected: Step.accepted)
        }
        return log.steps
    }

    var claims: Claims {
        [
            "iss": .string(issuer), "aud": .string(audience), "sub": "user-1", "role": "admin",
            "exp": .string(rfc3339(now + 3600)), "jti": .string(UUID().uuidString),
        ]
    }

    var rules: Rules {
        Rules(issuer: issuer, audience: audience, now: now)
    }

    func rfc3339(_ seconds: Int64) -> String {
        ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    func summary(_ claims: Claims) -> String {
        ["sub", "role", "aud"].compactMap { name in claims[name]?.stringValue.map { "\(name)=\($0)" } }
            .joined(separator: " ")
    }

    func preview(_ token: String) -> String {
        "\(token.prefix(32))... (\(token.utf8.count) bytes)"
    }
}
