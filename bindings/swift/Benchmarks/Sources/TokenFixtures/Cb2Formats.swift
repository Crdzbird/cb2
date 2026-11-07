import Cb2

private func cb2Claims() -> Claims {
    [
        "iss": .string(SharedClaims.issuer), "sub": .string(SharedClaims.subject),
        "aud": .string(SharedClaims.audience), "exp": .string(SharedClaims.rfc3339(SharedClaims.expiresAt)),
        "iat": .string(SharedClaims.rfc3339(SharedClaims.issuedAt)), "jti": .string(SharedClaims.jti),
        "role": .string(SharedClaims.role),
    ]
}

private let cb2Rules = Rules(issuer: SharedClaims.issuer, audience: SharedClaims.audience)

/// cb2.local: XChaCha20 and keyed BLAKE3 under a 32-byte key.
struct Cb2Local: TokenFormat {
    let key: LocalKey
    let claims = cb2Claims()

    init() throws {
        key = try LocalKey.generate()
    }

    func issue() throws -> String {
        try Token.seal(claims, key: key)
    }

    func verify(_ token: String) throws {
        _ = try Token.open(token, key: key, rules: cb2Rules)
    }
}

/// cb2.public: Ed25519 and ML-DSA-65 together, both required to verify.
struct Cb2Public: TokenFormat {
    let secret: SecretKey
    let publicKey: PublicKey
    let claims = cb2Claims()

    init() throws {
        secret = try SecretKey.generate()
        publicKey = try secret.publicKey()
    }

    func issue() throws -> String {
        try Token.sign(claims, key: secret)
    }

    func verify(_ token: String) throws {
        _ = try Token.verify(token, key: publicKey, rules: cb2Rules)
    }
}
