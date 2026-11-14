import Cb2

/// cb3.local: the cryptography of cb2.local with the claims as CBOR and a
/// 16-byte digest of the key id in the footer.
struct CompactLocal: TokenFormat {
    let key: LocalKey
    let claims = cb2Claims()

    init() throws {
        key = try LocalKey.generate()
    }

    func issue() throws -> String {
        try Compact.seal(claims, key: key)
    }

    func verify(_ token: String) throws {
        _ = try Compact.open(token, key: key, rules: cb2Rules)
    }
}

/// cb3.local under a claim table of the issuer and the audience, so iss
/// and aud travel as indexes.
struct CompactLocalTable: TokenFormat {
    let key: LocalKey
    let table: ClaimTable
    let claims = cb2Claims()

    init() throws {
        key = try LocalKey.generate()
        table = try ClaimTable([SharedClaims.issuer, SharedClaims.audience])
    }

    func issue() throws -> String {
        try Compact.seal(claims, key: key, table: table)
    }

    func verify(_ token: String) throws {
        _ = try Compact.open(token, key: key, table: table, rules: cb2Rules)
    }
}

/// cb3.public: the signatures of cb2.public over the compact payload.
struct CompactPublic: TokenFormat {
    let secret: SecretKey
    let publicKey: PublicKey
    let claims = cb2Claims()

    init() throws {
        secret = try SecretKey.generate()
        publicKey = try secret.publicKey()
    }

    func issue() throws -> String {
        try Compact.sign(claims, key: secret)
    }

    func verify(_ token: String) throws {
        _ = try Compact.verify(token, key: publicKey, rules: cb2Rules)
    }
}
