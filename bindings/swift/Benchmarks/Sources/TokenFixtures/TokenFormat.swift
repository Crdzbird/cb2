import Foundation

/// One token format under test: issues a token carrying the shared claims
/// and verifies one, checking signature or tag, expiry, issuer and audience.
public protocol TokenFormat: Sendable {
    /// Issues a token with fresh randomness where the format has any.
    func issue() async throws -> String
    /// Verifies the token and its claims; throws when it is refused.
    func verify(_ token: String) async throws
}

/// The claims every format carries: iss, sub, aud, exp, iat, jti and one
/// short custom claim, the same values in each.
public enum SharedClaims {
    /// The `iss` claim.
    public static let issuer = "https://issuer.example"
    /// The `sub` claim.
    public static let subject = "user-1"
    /// The `aud` claim, and the audience every verifier expects.
    public static let audience = "api"
    /// The `jti` claim.
    public static let jti = "5f0c8a52-3b1e-4c8e-9a51-6f4f8e2d1c07"
    /// The one custom claim.
    public static let role = "admin"
    /// The `iat` claim: when the process started, to the second.
    public static let issuedAt = Date(timeIntervalSince1970: TimeInterval(Int(Date().timeIntervalSince1970)))
    /// The `exp` claim, an hour after `iat`.
    public static let expiresAt = issuedAt.addingTimeInterval(3600)

    static func rfc3339(_ date: Date) -> String {
        ISO8601DateFormatter().string(from: date)
    }

    static func randomBytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}

/// A format of the comparison by name, made on demand.
public struct FormatEntry: Sendable {
    /// The row label, such as `"cb2.local"`.
    public let name: String
    /// Makes the format with fresh keys.
    public let make: @Sendable () async throws -> any TokenFormat
}

/// Every format of the comparison: the symmetric ones, then the signature
/// ones, cb2 first in each. ML-DSA-65 in jwt-kit needs macOS 26 and its SDK.
public enum Formats {
    /// The formats in table order.
    public static var all: [FormatEntry] {
        var entries = [
            FormatEntry(name: "cb2.local") { try Cb2Local() },
            FormatEntry(name: "JWT HS256 (jwt-kit)") { await JWTFormat.hs256() },
            FormatEntry(name: "PASETO v4.local (swift-paseto)") { PasetoLocal() },
            FormatEntry(name: "cb2.public") { try Cb2Public() },
            FormatEntry(name: "JWT EdDSA (jwt-kit)") { try await JWTFormat.eddsa() },
            FormatEntry(name: "JWT ES256 (jwt-kit)") { await JWTFormat.es256() },
        ]
        #if compiler(>=6.2)
            if #available(macOS 26, *) {
                entries.append(FormatEntry(name: "JWT ML-DSA-65 (jwt-kit)") { try await JWTFormat.mldsa65() })
            }
        #endif
        entries.append(FormatEntry(name: "PASETO v4.public (swift-paseto)") { PasetoPublic() })
        return entries
    }
}
