import Foundation

/// The validation rules of ``Token/open(_:key:rules:implicit:)`` and
/// ``Token/verify(_:key:rules:implicit:)``, one member per entry of the
/// rules JSON of the C ABI.
///
/// Every member is optional and an unset member keeps the library's
/// default: the clock as now, no skew, `exp` required, an expected audience
/// and issuer required. Rules are `Sendable`, so one value can be shared by
/// every request handler.
public struct Rules: Sendable {
    /// A replay check: answers true to accept the id, false or a thrown
    /// error to refuse it. It runs synchronously on the calling thread.
    public typealias ReplayCheck = @Sendable (String) throws -> Bool

    /// The clock as Unix seconds; nil uses the system clock.
    public var now: Int64?
    /// Seconds of tolerance on every time check.
    public var clockSkew: Int64?
    /// Whether a token without `exp` is refused (the default) or accepted.
    public var requireExp: Bool?
    /// Accept any audience instead of requiring ``audience``.
    public var allowAnyAudience: Bool?
    /// Accept any issuer instead of requiring ``issuer``.
    public var allowAnyIssuer: Bool?
    /// The expected issuer.
    public var issuer: String?
    /// The expected audience.
    public var audience: String?
    /// The expected subject.
    public var subject: String?
    /// The largest token accepted, 16384 bytes by default.
    public var maxTokenBytes: Int?
    /// The longest lifetime (`exp` minus `iat` or now) accepted, in seconds.
    public var maxLifetime: Int64?
    /// Refuse a token without `cnf`.
    public var requireCnf: Bool?
    /// Accept a bound token without checking a holder proof.
    public var ignoreCnf: Bool?
    /// The holder proof presented with the request.
    public var proof: String?
    /// The request the holder proof must be for.
    public var request: HolderRequest?
    /// The longest a holder proof lives, 60 seconds by default.
    public var proofLifetime: Int64?
    /// Ids a built-in replay check refuses, for tests and simple stores;
    /// it takes precedence over ``replay``.
    public var seenJti: [String]?
    /// Proof ids a built-in proof replay check refuses; it takes precedence
    /// over ``proofReplay``.
    public var proofSeenJti: [String]?
    /// The replay check run on the token's `jti`.
    public var replay: ReplayCheck?
    /// The replay check run on the holder proof's `jti`. A proof presented
    /// without this or ``proofSeenJti`` is ``Cb2Error/rulesIncomplete``.
    public var proofReplay: ReplayCheck?

    /// Rules with the members most verifiers set; every other member starts
    /// unset and can be assigned afterwards.
    public init(issuer: String? = nil, audience: String? = nil, now: Int64? = nil) {
        self.issuer = issuer
        self.audience = audience
        self.now = now
    }

    func json() throws(Cb2Error) -> Data {
        let wire = RulesJSON(
            now: now, clockSkew: clockSkew, requireExp: requireExp, allowAnyAudience: allowAnyAudience,
            allowAnyIssuer: allowAnyIssuer, issuer: issuer, audience: audience, subject: subject,
            maxTokenBytes: maxTokenBytes, maxLifetime: maxLifetime, requireCnf: requireCnf, ignoreCnf: ignoreCnf,
            proof: proof, request: request, proofLifetime: proofLifetime, seenJti: seenJti,
            proofSeenJti: proofSeenJti, replay: replay == nil ? nil : true
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        encoder.keyEncodingStrategy = .convertToSnakeCase
        do {
            return try encoder.encode(wire)
        } catch {
            throw .argument
        }
    }
}

private struct RulesJSON: Encodable {
    let now: Int64?
    let clockSkew: Int64?
    let requireExp: Bool?
    let allowAnyAudience: Bool?
    let allowAnyIssuer: Bool?
    let issuer: String?
    let audience: String?
    let subject: String?
    let maxTokenBytes: Int?
    let maxLifetime: Int64?
    let requireCnf: Bool?
    let ignoreCnf: Bool?
    let proof: String?
    let request: HolderRequest?
    let proofLifetime: Int64?
    let seenJti: [String]?
    let proofSeenJti: [String]?
    let replay: Bool?
}
