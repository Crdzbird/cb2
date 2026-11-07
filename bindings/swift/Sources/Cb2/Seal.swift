import CCb2

/// Key sealing: a local key to a recipient's public key, as `kcb2.seal`
/// (X-Wing). Available only when ``Library/hasSeal`` is true.
public enum Seal {
    /// Seals `key` to the recipient.
    public static func seal(_ key: LocalKey, to recipient: RecipientPublicKey) throws(Cb2Error) -> String {
        let text = try recipient.handle.use { to in
            key.handle.use { inner in
                var out: UnsafeMutablePointer<CChar>? = nil
                let code = cb2_seal(to, inner, &out)
                return Bridge.result(code, Bridge.text(out))
            }
        }.get()
        return try Bridge.required(text)
    }

    /// Unseals a `kcb2.seal` text with the recipient pair it was sealed to;
    /// any other pair is ``Cb2Error/invalid``.
    public static func unseal(_ text: String, by recipient: RecipientKey) throws(Cb2Error) -> LocalKey {
        LocalKey(
            try Bridge.handle { out in
                recipient.handle.use { by in
                    Bridge.withText(text) { cb2_unseal($0.text, $0.count, by, out) }
                }
            })
    }
}
