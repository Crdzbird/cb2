import Paseto

private func pasetoClaims() -> Token {
    Token(claims: [
        "iss": SharedClaims.issuer, "sub": SharedClaims.subject, "aud": SharedClaims.audience,
        "exp": SharedClaims.rfc3339(SharedClaims.expiresAt), "iat": SharedClaims.rfc3339(SharedClaims.issuedAt),
        "jti": SharedClaims.jti, "role": SharedClaims.role,
    ])
}

private func pasetoRules() -> [Rule] {
    [Rules.notExpired(), Rules.issuedBy(SharedClaims.issuer), Rules.forAudience(SharedClaims.audience)]
}

/// PASETO v4.local of aidantwoods/swift-paseto: XChaCha20 and keyed BLAKE2b.
///
/// `@unchecked Sendable` because swift-paseto predates Sendable; the key and
/// token and parser are values never mutated after init.
struct PasetoLocal: TokenFormat, @unchecked Sendable {
    let key = Version4.SymmetricKey()
    let token = pasetoClaims()
    let parser = Parser<Version4.Local>(rules: pasetoRules())

    func issue() throws -> String {
        try token.encrypt(with: key)
    }

    func verify(_ token: String) throws {
        _ = try parser.decrypt(token, with: key)
    }
}

/// PASETO v4.public of aidantwoods/swift-paseto: Ed25519.
///
/// `@unchecked Sendable` for the same reason as ``PasetoLocal``.
struct PasetoPublic: TokenFormat, @unchecked Sendable {
    let secret = Version4.AsymmetricSecretKey()
    let token = pasetoClaims()
    let parser = Parser<Version4.Public>(rules: pasetoRules())

    func issue() throws -> String {
        try token.sign(with: secret)
    }

    func verify(_ token: String) throws {
        _ = try parser.verify(token, with: secret.publicKey)
    }
}
