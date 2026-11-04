import CCb2

/// A verdict of the library other than success: the numeric code of the
/// C ABI and the stable name the library gives it ("invalid", "expired").
public struct Cb2Error: Error, Hashable, CustomStringConvertible {
    /// The verdicts of the C ABI, in the order of docs/PROTOCOL.md.
    public enum Code: Int32, Sendable {
        case invalid = 1
        case tooLarge = 2
        case argument = 3
        case rulesIncomplete = 4
        case `internal` = 5
        case unavailable = 6
        case claimsMalformed = 7
        case missingExp = 8
        case expired = 9
        case notYetValid = 10
        case issuedInFuture = 11
        case lifetimeExceeded = 12
        case issuerMismatch = 13
        case audienceMismatch = 14
        case subjectMismatch = 15
        case missingJti = 16
        case replayed = 17
        case missingCnf = 18
        case missingProof = 19
        case proofInvalid = 20
        case proofMalformed = 21
        case proofExpired = 22
        case proofMismatch = 23
        case proofReplayed = 24
    }

    /// The code as the C ABI returned it.
    public let code: Int32

    /// The library's name for the code, "unknown" for a code it does not have.
    public let name: String

    /// The code as a case, nil when the library returned a code this
    /// package does not know.
    public var kind: Code? { Code(rawValue: code) }

    public init(code: Int32) {
        self.code = code
        self.name = String(cString: cb2_error_name(code))
    }

    public init(_ kind: Code) {
        self.init(code: kind.rawValue)
    }

    public var description: String { "cb2 error \(code) (\(name))" }
}
