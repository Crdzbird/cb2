import CCb2

/// The build of the cb2 library behind the C ABI.
public enum Library {
    /// The version of the library, such as `"0.1.0"`.
    public static var version: String {
        String(cString: cb2_version())
    }

    /// The ABI version of the C library; it changes only when a call of
    /// `cb2_c.h` changes incompatibly.
    public static var abiVersion: Int {
        Int(cb2_abi_version())
    }

    /// Whether this build has cb2.public: signing pairs, public tokens and
    /// public-mode holder proofs.
    public static var hasPublic: Bool {
        cb2_has_public() != 0
    }

    /// Whether this build has `kcb2.seal`: recipient pairs and sealing.
    public static var hasSeal: Bool {
        cb2_has_seal() != 0
    }
}
