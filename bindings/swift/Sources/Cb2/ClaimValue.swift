/// The claims of a token: a JSON object of registered claims (times as
/// RFC 3339 strings, such as `"exp": "2099-01-01T00:00:00+00:00"`) and
/// custom claims.
public typealias Claims = [String: ClaimValue]

/// One JSON value of a claims object.
///
/// Literals build values directly, so a claims object reads like JSON:
///
/// ```swift
/// let claims: Claims = ["sub": "user-1", "scope": ["read", "write"], "level": 3]
/// ```
public enum ClaimValue: Hashable, Sendable {
    /// A JSON string.
    case string(String)
    /// A JSON number without a fraction or exponent that fits in 64 bits.
    case integer(Int64)
    /// Any other JSON number.
    case number(Double)
    /// `true` or `false`.
    case bool(Bool)
    /// A JSON array.
    case array([ClaimValue])
    /// A JSON object.
    case object([String: ClaimValue])
    /// `null`.
    case null

    /// The string, or nil when the value is not a string.
    public var stringValue: String? {
        guard case .string(let value) = self else {
            return nil
        }
        return value
    }

    /// The integer, or nil when the value is not an integer.
    public var integerValue: Int64? {
        guard case .integer(let value) = self else {
            return nil
        }
        return value
    }

    /// The number as a `Double`, for integers and other numbers alike.
    public var doubleValue: Double? {
        switch self {
        case .integer(let value): Double(value)
        case .number(let value): value
        default: nil
        }
    }

    /// The Boolean, or nil when the value is not one.
    public var boolValue: Bool? {
        guard case .bool(let value) = self else {
            return nil
        }
        return value
    }

    /// The elements, or nil when the value is not an array.
    public var arrayValue: [ClaimValue]? {
        guard case .array(let value) = self else {
            return nil
        }
        return value
    }

    /// The members, or nil when the value is not an object.
    public var objectValue: [String: ClaimValue]? {
        guard case .object(let value) = self else {
            return nil
        }
        return value
    }
}
