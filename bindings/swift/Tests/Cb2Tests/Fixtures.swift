import Cb2
import Foundation

/// The claims, rules and request the suites share, the ones
/// bindings/c/test/test_c.c uses.
enum Fixtures {
    static let now: Int64 = 1_700_000_000

    static let claims: Claims = [
        "iss": "https://issuer.example",
        "sub": "user-1",
        "aud": "api",
        "exp": "2099-01-01T00:00:00+00:00",
        "jti": "id-1",
        "role": "admin",
    ]

    static let rules = Rules(issuer: "https://issuer.example", audience: "api", now: now)

    static let request = HolderRequest(htm: "GET", htu: "https://api.example/v1/me")

    static func bound(to cnf: String) -> Claims {
        ["iss": "https://issuer.example", "aud": "api", "exp": "2099-01-01T00:00:00+00:00", "cnf": .string(cnf)]
    }

    static func rules(proof: String, request: HolderRequest, seen: [String]? = nil) -> Rules {
        var rules = Self.rules
        rules.proof = proof
        rules.request = request
        rules.proofSeenJti = seen
        return rules
    }
}

/// A replay store for tests: remembers ids under a lock, the shape a real
/// store shared by request handlers has.
final class SeenStore: @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [String] = []

    var ids: [String] {
        lock.withLock { seen }
    }

    func accept(_ id: String) -> Bool {
        lock.withLock {
            guard !seen.contains(id) else {
                return false
            }
            seen.append(id)
            return true
        }
    }
}
