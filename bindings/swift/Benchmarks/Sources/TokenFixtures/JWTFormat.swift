import Foundation
import JWTKit

/// The shared claims as a jwt-kit payload; verifying checks expiry,
/// audience and issuer, as the cb2 and PASETO rows do.
struct JWTClaims: JWTPayload {
    var iss: IssuerClaim
    var sub: SubjectClaim
    var aud: AudienceClaim
    var exp: ExpirationClaim
    var iat: IssuedAtClaim
    var jti: IDClaim
    var role: String

    static let shared = JWTClaims(
        iss: IssuerClaim(value: SharedClaims.issuer), sub: SubjectClaim(value: SharedClaims.subject),
        aud: AudienceClaim(value: SharedClaims.audience), exp: ExpirationClaim(value: SharedClaims.expiresAt),
        iat: IssuedAtClaim(value: SharedClaims.issuedAt), jti: IDClaim(value: SharedClaims.jti),
        role: SharedClaims.role)

    func verify(using algorithm: some JWTAlgorithm) async throws {
        try exp.verifyNotExpired()
        try aud.verifyIntendedAudience(includes: SharedClaims.audience)
        guard iss.value == SharedClaims.issuer else {
            throw JWTError.claimVerificationFailure(failedClaim: iss, reason: "unexpected issuer")
        }
    }
}

/// A JWT format of vapor/jwt-kit, one key in a key collection.
struct JWTFormat: TokenFormat {
    let keys: JWTKeyCollection

    func issue() async throws -> String {
        try await keys.sign(JWTClaims.shared)
    }

    func verify(_ token: String) async throws {
        _ = try await keys.verify(token, as: JWTClaims.self)
    }

    static func hs256() async -> JWTFormat {
        let keys = JWTKeyCollection()
        await keys.add(hmac: HMACKey(from: SharedClaims.randomBytes(32)), digestAlgorithm: .sha256)
        return JWTFormat(keys: keys)
    }

    static func eddsa() async throws -> JWTFormat {
        let keys = JWTKeyCollection()
        await keys.add(eddsa: try EdDSA.PrivateKey())
        return JWTFormat(keys: keys)
    }

    static func es256() async -> JWTFormat {
        let keys = JWTKeyCollection()
        await keys.add(ecdsa: ES256PrivateKey())
        return JWTFormat(keys: keys)
    }

    #if compiler(>=6.2)
        @available(macOS 26, *)
        static func mldsa65() async throws -> JWTFormat {
            let keys = JWTKeyCollection()
            await keys.add(mldsa: try MLDSA65PrivateKey(seedRepresentation: SharedClaims.randomBytes(32)))
            return JWTFormat(keys: keys)
        }
    #endif
}
