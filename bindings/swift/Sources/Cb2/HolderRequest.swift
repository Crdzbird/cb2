/// The HTTP request a holder proof is made for and checked against.
public struct HolderRequest: Hashable, Sendable, Encodable {
    /// The request method, such as `"GET"`.
    public var htm: String
    /// The request target; the library normalizes it before comparing
    /// (see ``Holder/normalizeTarget(_:)``).
    public var htu: String
    /// The server nonce, when the server issued one.
    public var nonce: String?

    /// A request by method, target and optional nonce.
    public init(htm: String, htu: String, nonce: String? = nil) {
        self.htm = htm
        self.htu = htu
        self.nonce = nonce
    }
}
