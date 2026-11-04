import CCb2

/// Key sealing: a local key to a recipient's public key, as kcb2.seal.
/// Available only when hasSeal() is true.
public enum Seal {
    public static func seal(_ key: LocalKey, to recipient: RecipientPublicKey) throws -> String {
        var out: UnsafeMutablePointer<CChar>? = nil
        try Bridge.check(cb2_seal(recipient.handle, key.handle, &out))
        return try Bridge.required(Bridge.text(out))
    }

    public static func unseal(_ text: String, by recipient: RecipientKey) throws -> LocalKey {
        let handle = try Bridge.handle { out in
            Bridge.withText(text) { cb2_unseal($0.text, $0.count, recipient.handle, out) }
        }
        return LocalKey(handle: handle)
    }
}
