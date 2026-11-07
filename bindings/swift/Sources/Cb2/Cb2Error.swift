import CCb2
import Foundation

/// A verdict of the library other than success.
///
/// Every throwing function of this package throws `Cb2Error` and nothing
/// else, so a `catch` can switch over the verdicts directly. The cases and
/// their order are those of the C ABI (`cb2_c.h`) and of `docs/PROTOCOL.md`.
public enum Cb2Error: Error, Hashable, Sendable {
    /// The token, proof or key text failed authentication or parsing.
    case invalid
    /// The input exceeded a size limit.
    case tooLarge
    /// An argument was refused: wrong length, weak key, bad identifier.
    case argument
    /// The rules lack something the library requires, such as an audience.
    case rulesIncomplete
    /// The library failed internally.
    case `internal`
    /// The operation is not in this build of the library.
    case unavailable
    /// The claims are not a JSON object the library accepts.
    case claimsMalformed
    /// The claims have no `exp` and the rules require one.
    case missingExp
    /// The token has expired.
    case expired
    /// The token is not valid yet (`nbf`).
    case notYetValid
    /// The token was issued in the future (`iat`).
    case issuedInFuture
    /// The token lives longer than `maxLifetime` allows.
    case lifetimeExceeded
    /// The issuer is not the expected one.
    case issuerMismatch
    /// The audience is not the expected one.
    case audienceMismatch
    /// The subject is not the expected one.
    case subjectMismatch
    /// A replay check was asked for and the token has no `jti`.
    case missingJti
    /// The token's `jti` was seen before.
    case replayed
    /// The rules require `cnf` and the token has none.
    case missingCnf
    /// The token is bound by `cnf` and no holder proof was presented.
    case missingProof
    /// The holder proof failed authentication.
    case proofInvalid
    /// The holder proof could not be parsed.
    case proofMalformed
    /// The holder proof has expired.
    case proofExpired
    /// The holder proof is for another request or another token.
    case proofMismatch
    /// The holder proof's `jti` was seen before.
    case proofReplayed
    /// A code this package does not know, as the C ABI returned it.
    case unknown(Int32)

    private static let known: [Cb2Error] = [
        .invalid, .tooLarge, .argument, .rulesIncomplete, .internal, .unavailable, .claimsMalformed,
        .missingExp, .expired, .notYetValid, .issuedInFuture, .lifetimeExceeded, .issuerMismatch,
        .audienceMismatch, .subjectMismatch, .missingJti, .replayed, .missingCnf, .missingProof,
        .proofInvalid, .proofMalformed, .proofExpired, .proofMismatch, .proofReplayed,
    ]

    /// The verdict for a code of the C ABI.
    public init(code: Int32) {
        guard code >= 1, Int(code) <= Self.known.count else {
            self = .unknown(code)
            return
        }
        self = Self.known[Int(code) - 1]
    }

    /// The code as the C ABI returns it.
    public var code: Int32 {
        if case .unknown(let code) = self {
            return code
        }
        return Int32((Self.known.firstIndex(of: self) ?? -1) + 1)
    }

    /// The library's stable name for the verdict, such as `"expired"`,
    /// or `"unknown"` for a code the library does not have.
    public var name: String {
        String(cString: cb2_error_name(code))
    }
}

extension Cb2Error: CustomStringConvertible, LocalizedError {
    /// The code and the name, as in `cb2 error 9 (expired)`.
    public var description: String {
        "cb2 error \(code) (\(name))"
    }

    /// The library's name for the verdict.
    public var errorDescription: String? {
        name
    }
}
