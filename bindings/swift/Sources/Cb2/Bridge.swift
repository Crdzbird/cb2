import CCb2
import Foundation

/// A borrowed view of one argument's bytes for the duration of a C call.
struct Buffer {
    let base: UnsafePointer<UInt8>?
    let count: Int

    var text: UnsafePointer<CChar>? {
        base.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) }
    }
}

/// The marshalling every call shares: verdict checks, handle creation,
/// borrowed input buffers, and results copied out of C memory and freed.
enum Bridge {
    static func check(_ code: Int32) throws {
        if code != 0 {
            throw Cb2Error(code: code)
        }
    }

    static func handle(_ make: (UnsafeMutablePointer<OpaquePointer?>) throws -> Int32) throws -> OpaquePointer {
        var out: OpaquePointer? = nil
        try check(try make(&out))
        guard let out else {
            throw Cb2Error(.internal)
        }
        return out
    }

    static func text(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else {
            return nil
        }
        defer { cb2_free(p) }
        return String(cString: p)
    }

    static func text(_ p: UnsafeMutablePointer<CChar>?, count: Int) -> String {
        guard let p else {
            return ""
        }
        defer { cb2_free(p) }
        return String(decoding: UnsafeRawBufferPointer(start: p, count: count), as: UTF8.self)
    }

    static func secret(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else {
            return nil
        }
        defer { cb2_free_secret(p) }
        return String(cString: p)
    }

    static func required(_ s: String?) throws -> String {
        guard let s else {
            throw Cb2Error(.unavailable)
        }
        return s
    }

    static func bytes(_ p: UnsafeMutablePointer<UInt8>?, count: Int) -> Data {
        guard let p else {
            return Data()
        }
        defer { cb2_free(p) }
        return Data(bytes: p, count: count)
    }

    static func withBytes<T>(_ data: Data?, _ body: (Buffer) throws -> T) rethrows -> T {
        guard let data, !data.isEmpty else {
            return try body(Buffer(base: nil, count: 0))
        }
        return try data.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else {
                return try body(Buffer(base: nil, count: 0))
            }
            return try body(Buffer(base: base.assumingMemoryBound(to: UInt8.self), count: raw.count))
        }
    }

    static func withText<T>(_ s: String?, _ body: (Buffer) throws -> T) rethrows -> T {
        try withBytes(s.map { Data($0.utf8) }, body)
    }

    static func withBuffers<T>(_ items: [Data?], _ body: ([Buffer]) throws -> T) rethrows -> T {
        try withBuffers(items[...], [], body)
    }

    private static func withBuffers<T>(_ items: ArraySlice<Data?>, _ acc: [Buffer], _ body: ([Buffer]) throws -> T) rethrows -> T {
        guard let first = items.first else {
            return try body(acc)
        }
        return try withBytes(first) { buffer in
            try withBuffers(items.dropFirst(), acc + [buffer], body)
        }
    }

    static func claimsJson(_ claims: [String: Any]) throws -> Data {
        guard JSONSerialization.isValidJSONObject(claims) else {
            throw Cb2Error(.argument)
        }
        return try JSONSerialization.data(withJSONObject: claims, options: [.sortedKeys])
    }

    static func claims(from json: String) throws -> [String: Any] {
        let value = try JSONSerialization.jsonObject(with: Data(json.utf8))
        guard let object = value as? [String: Any] else {
            throw Cb2Error(.claimsMalformed)
        }
        return object
    }
}
