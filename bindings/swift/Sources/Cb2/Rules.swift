import Foundation

/// The validation rules of Token.open and Token.verify, one member per
/// entry of the rules JSON the C ABI takes. Every member is optional and
/// an unset member keeps the library's default: the clock as now, no
/// skew, exp required, an expected audience and issuer required.
public struct Rules {
    /// The request a holder proof is checked against.
    public struct Request {
        public var htm: String
        public var htu: String
        public var nonce: String?

        public init(htm: String, htu: String, nonce: String? = nil) {
            self.htm = htm
            self.htu = htu
            self.nonce = nonce
        }

        var json: [String: Any] {
            var object: [String: Any] = ["htm": htm, "htu": htu]
            object["nonce"] = nonce
            return object
        }
    }

    public var now: Int64?
    public var clockSkew: Int64?
    public var requireExp: Bool?
    public var allowAnyAudience: Bool?
    public var allowAnyIssuer: Bool?
    public var issuer: String?
    public var audience: String?
    public var subject: String?
    public var maxTokenBytes: Int?
    public var maxLifetime: Int64?
    public var requireCnf: Bool?
    public var ignoreCnf: Bool?
    public var proof: String?
    public var request: Request?
    public var proofLifetime: Int64?

    /// Ids a built-in replay check refuses, for tests and simple stores.
    public var seenJti: [String]?

    /// Proof ids a built-in proof replay check refuses.
    public var proofSeenJti: [String]?

    /// The replay check run on the token's jti: true accepts the id. An
    /// error thrown inside refuses the id; seenJti takes precedence.
    public var replay: ((String) throws -> Bool)?

    /// The replay check run on the proof's jti: true accepts the id. An
    /// error thrown inside refuses the id; proofSeenJti takes precedence.
    public var proofReplay: ((String) throws -> Bool)?

    public init() {}

    func json() throws -> Data {
        var object: [String: Any] = [:]
        object["now"] = now
        object["clock_skew"] = clockSkew
        object["require_exp"] = requireExp
        object["allow_any_audience"] = allowAnyAudience
        object["allow_any_issuer"] = allowAnyIssuer
        object["issuer"] = issuer
        object["audience"] = audience
        object["subject"] = subject
        object["max_token_bytes"] = maxTokenBytes
        object["max_lifetime"] = maxLifetime
        object["require_cnf"] = requireCnf
        object["ignore_cnf"] = ignoreCnf
        object["proof"] = proof
        object["proof_lifetime"] = proofLifetime
        object["seen_jti"] = seenJti
        object["proof_seen_jti"] = proofSeenJti
        object["replay"] = replay == nil ? nil : true
        object["request"] = request?.json
        return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    }
}
