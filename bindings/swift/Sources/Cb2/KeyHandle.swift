import CCb2
import Foundation

/// Owns one C key handle and releases it with the matching free function.
///
/// `@unchecked Sendable` rests on two facts: the handle is never mutated
/// once a `KeyHandle` exists (a key id is set on a fresh handle before it
/// is wrapped, see `LocalKey.withKeyId(_:)`), and the library's read-only
/// key operations are safe to run from several threads at once.
final class KeyHandle: @unchecked Sendable {
    private let pointer: OpaquePointer
    private let release: (OpaquePointer) -> Void

    init(_ pointer: OpaquePointer, release: @escaping (OpaquePointer) -> Void) {
        self.pointer = pointer
        self.release = release
    }

    deinit {
        release(pointer)
    }

    /// Runs body with the raw handle, keeping this owner alive throughout.
    func use<T>(_ body: (OpaquePointer) -> T) -> T {
        withExtendedLifetime(self) { body(pointer) }
    }

    /// A new handle made from this key's PASERK text, with the key id
    /// adjusted on the fresh handle before it is wrapped. The text never
    /// becomes a Swift string; secret text is wiped as it is freed.
    func copy(
        export: (OpaquePointer) -> UnsafeMutablePointer<CChar>?,
        secret: Bool,
        import make: (UnsafePointer<CChar>, Int, UnsafeMutablePointer<OpaquePointer?>) -> Int32,
        adjust: (OpaquePointer) -> Int32
    ) throws(Cb2Error) -> KeyHandle {
        let result: Result<OpaquePointer, Cb2Error> = use { pointer in
            guard let text = export(pointer) else {
                return .failure(.unavailable)
            }
            defer { secret ? cb2_free_secret(text) : cb2_free(text) }
            var out: OpaquePointer? = nil
            let code = make(text, strlen(text), &out)
            guard code == 0, let out else {
                return .failure(Cb2Error(code: code == 0 ? Cb2Error.internal.code : code))
            }
            let adjusted = adjust(out)
            guard adjusted == 0 else {
                self.release(out)
                return .failure(Cb2Error(code: adjusted))
            }
            return .success(out)
        }
        return KeyHandle(try result.get(), release: release)
    }
}
