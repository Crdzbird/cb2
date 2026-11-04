import CCb2

/// The version of the cb2 library behind the C ABI.
public func version() -> String {
    String(cString: cb2_version())
}

/// Whether this build of the library has cb2.public (signing pairs, holder proofs).
public func hasPublic() -> Bool {
    cb2_has_public() != 0
}

/// Whether this build of the library has kcb2.seal (recipient pairs).
public func hasSeal() -> Bool {
    cb2_has_seal() != 0
}
