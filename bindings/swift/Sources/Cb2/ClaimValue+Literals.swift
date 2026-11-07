extension ClaimValue: ExpressibleByStringLiteral {
    /// A string value.
    public init(stringLiteral value: String) {
        self = .string(value)
    }
}

extension ClaimValue: ExpressibleByIntegerLiteral {
    /// An integer value.
    public init(integerLiteral value: Int64) {
        self = .integer(value)
    }
}

extension ClaimValue: ExpressibleByFloatLiteral {
    /// A number value.
    public init(floatLiteral value: Double) {
        self = .number(value)
    }
}

extension ClaimValue: ExpressibleByBooleanLiteral {
    /// A Boolean value.
    public init(booleanLiteral value: Bool) {
        self = .bool(value)
    }
}

extension ClaimValue: ExpressibleByArrayLiteral {
    /// An array value.
    public init(arrayLiteral elements: ClaimValue...) {
        self = .array(elements)
    }
}

extension ClaimValue: ExpressibleByDictionaryLiteral {
    /// An object value; a repeated key keeps its last value.
    public init(dictionaryLiteral elements: (String, ClaimValue)...) {
        self = .object(Dictionary(elements, uniquingKeysWith: { _, last in last }))
    }
}

extension ClaimValue: ExpressibleByNilLiteral {
    /// The null value.
    public init(nilLiteral: ()) {
        self = .null
    }
}
