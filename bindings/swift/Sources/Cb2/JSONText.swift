import Foundation

/// The JSON text that crosses the C boundary: claims and rules written
/// byte by byte, and claims read back through `JSONSerialization`. The C
/// library parses and checks both strictly, so this layer only has to be
/// correct and fast, not a general JSON library.
enum JSONText {
    static func write(_ value: ClaimValue, into out: inout [UInt8]) throws(Cb2Error) {
        switch value {
        case .string(let text):
            writeString(text, into: &out)
        case .integer(let number):
            out.append(contentsOf: String(number).utf8)
        case .number(let number):
            guard number.isFinite else {
                throw .argument
            }
            out.append(contentsOf: "\(number)".utf8)
        case .bool(let flag):
            out.append(contentsOf: (flag ? "true" : "false").utf8)
        case .null:
            out.append(contentsOf: "null".utf8)
        case .array(let items):
            out.append(UInt8(ascii: "["))
            for (index, item) in items.enumerated() {
                if index > 0 {
                    out.append(UInt8(ascii: ","))
                }
                try write(item, into: &out)
            }
            out.append(UInt8(ascii: "]"))
        case .object(let members):
            try writeObject(members, into: &out)
        }
    }

    static func writeObject(_ members: [String: ClaimValue], into out: inout [UInt8]) throws(Cb2Error) {
        out.append(UInt8(ascii: "{"))
        for (index, key) in members.keys.sorted().enumerated() {
            if index > 0 {
                out.append(UInt8(ascii: ","))
            }
            writeString(key, into: &out)
            out.append(UInt8(ascii: ":"))
            if let value = members[key] {
                try write(value, into: &out)
            }
        }
        out.append(UInt8(ascii: "}"))
    }

    static func writeString(_ text: String, into out: inout [UInt8]) {
        out.append(UInt8(ascii: "\""))
        for byte in text.utf8 {
            switch byte {
            case UInt8(ascii: "\""), UInt8(ascii: "\\"):
                out.append(UInt8(ascii: "\\"))
                out.append(byte)
            case 0..<0x20:
                out.append(contentsOf: "\\u00".utf8)
                out.append(hexDigits[Int(byte >> 4)])
                out.append(hexDigits[Int(byte & 0x0F)])
            default:
                out.append(byte)
            }
        }
        out.append(UInt8(ascii: "\""))
    }

    private static let hexDigits = Array("0123456789abcdef".utf8)

    static func readClaims(_ text: String) throws(Cb2Error) -> Claims {
        guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw .claimsMalformed
        }
        return try claimValues(object)
    }

    private static func claimValues(_ members: [String: Any]) throws(Cb2Error) -> [String: ClaimValue] {
        var values: [String: ClaimValue] = [:]
        values.reserveCapacity(members.count)
        for (key, member) in members {
            values[key] = try claimValue(member)
        }
        return values
    }

    private static func claimValue(_ value: Any) throws(Cb2Error) -> ClaimValue {
        switch value {
        case let text as String:
            return .string(text)
        case let number as NSNumber:
            return claimValue(number)
        case let items as [Any]:
            return .array(try items.map { (item: Any) throws(Cb2Error) -> ClaimValue in try claimValue(item) })
        case let members as [String: Any]:
            return .object(try claimValues(members))
        case is NSNull:
            return .null
        default:
            throw .claimsMalformed
        }
    }

    private static func claimValue(_ number: NSNumber) -> ClaimValue {
        if CFGetTypeID(number) == CFBooleanGetTypeID() {
            return .bool(number.boolValue)
        }
        if number is NSDecimalNumber || CFNumberIsFloatType(number) {
            return .number(number.doubleValue)
        }
        return .integer(number.int64Value)
    }
}
