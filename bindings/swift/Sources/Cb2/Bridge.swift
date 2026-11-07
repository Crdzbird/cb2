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

/// The marshalling every call shares: verdicts, handle creation, borrowed
/// input buffers, and results copied out of C memory and freed. Closures
/// passed to the C side never throw; a verdict travels back as a `Result`.
enum Bridge {
    static func check(_ code: Int32) throws(Cb2Error) {
        guard code == 0 else {
            throw Cb2Error(code: code)
        }
    }

    static func result<T>(_ code: Int32, _ value: T) -> Result<T, Cb2Error> {
        code == 0 ? .success(value) : .failure(Cb2Error(code: code))
    }

    static func handle(_ make: (UnsafeMutablePointer<OpaquePointer?>) -> Int32) throws(Cb2Error) -> OpaquePointer {
        var out: OpaquePointer? = nil
        try check(make(&out))
        guard let out else {
            throw .internal
        }
        return out
    }

    static func text(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else {
            return nil
        }
        defer { cb2_free(pointer) }
        return String(cString: pointer)
    }

    static func text(_ pointer: UnsafeMutablePointer<CChar>?, count: Int) -> String {
        guard let pointer else {
            return ""
        }
        defer { cb2_free(pointer) }
        return String(decoding: UnsafeRawBufferPointer(start: pointer, count: count), as: UTF8.self)
    }

    static func secret(_ pointer: UnsafeMutablePointer<CChar>?) -> String? {
        guard let pointer else {
            return nil
        }
        defer { cb2_free_secret(pointer) }
        return String(cString: pointer)
    }

    static func required(_ value: String?) throws(Cb2Error) -> String {
        guard let value else {
            throw .internal
        }
        return value
    }

    static func bytes(_ pointer: UnsafeMutablePointer<UInt8>?, count: Int) -> Data {
        guard let pointer else {
            return Data()
        }
        defer { cb2_free(pointer) }
        return Data(bytes: pointer, count: count)
    }

    static func withBytes<T>(_ data: Data?, _ body: (Buffer) -> T) -> T {
        guard let data, !data.isEmpty else {
            return body(Buffer(base: nil, count: 0))
        }
        return data.withUnsafeBytes { raw in
            body(Buffer(base: raw.bindMemory(to: UInt8.self).baseAddress, count: raw.count))
        }
    }

    static func withText<T>(_ text: String?, _ body: (Buffer) -> T) -> T {
        withBytes(text.map { Data($0.utf8) }, body)
    }

    static func withBuffers<T>(_ items: [Data?], _ body: ([Buffer]) -> T) -> T {
        withBuffers(items[...], [], body)
    }

    private static func withBuffers<T>(
        _ items: ArraySlice<Data?>,
        _ done: [Buffer],
        _ body: ([Buffer]) -> T
    ) -> T {
        guard let first = items.first else {
            return body(done)
        }
        return withBytes(first) { buffer in
            withBuffers(items.dropFirst(), done + [buffer], body)
        }
    }

    static func texts(_ items: [String?]) -> [Data?] {
        items.map { $0.map { Data($0.utf8) } }
    }

    static func encode(_ claims: Claims) throws(Cb2Error) -> Data {
        var out: [UInt8] = []
        out.reserveCapacity(256)
        try JSONText.writeObject(claims, into: &out)
        return Data(out)
    }

    static func decode(_ json: String) throws(Cb2Error) -> Claims {
        try JSONText.readClaims(json)
    }
}
