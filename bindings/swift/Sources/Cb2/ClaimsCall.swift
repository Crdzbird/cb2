import CCb2
import Foundation

/// The claims-token calls of the C ABI come in two shapes, issue and check,
/// shared by the cb2 and compact formats. ``Token`` and ``Compact`` pass the
/// C function of their format; the marshalling is written once here.
enum ClaimsCall {
    typealias Issue = (
        OpaquePointer?, UnsafePointer<CChar>?, Int, UnsafePointer<UInt8>?, Int,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, UnsafeMutablePointer<Int>?
    ) -> Int32

    typealias Check = (
        OpaquePointer?, UnsafePointer<CChar>?, Int, UnsafePointer<CChar>?, Int, UnsafePointer<UInt8>?, Int,
        cb2_replay_fn?, cb2_replay_fn?, UnsafeMutableRawPointer?,
        UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?, UnsafeMutablePointer<Int>?
    ) -> Int32

    static func issue(
        _ call: Issue,
        _ claims: Claims,
        handle: KeyHandle,
        implicit: Data?
    ) throws(Cb2Error) -> String {
        let json = try Bridge.encode(claims)
        return try Bridge.withBuffers([json, implicit]) { b in
            handle.use { pointer in
                var out: UnsafeMutablePointer<CChar>? = nil
                var count = 0
                let code = call(pointer, b[0].text, b[0].count, b[1].base, b[1].count, &out, &count)
                return Bridge.result(code, Bridge.text(out, count: count))
            }
        }.get()
    }

    static func check(
        _ call: Check,
        _ token: String,
        handle: KeyHandle,
        rules: Rules,
        implicit: Data?
    ) throws(Cb2Error) -> Claims {
        let json = try rules.json()
        let replay = ReplayBridge(rules)
        let text = try Bridge.withBuffers([Data(token.utf8), json, implicit]) { b in
            handle.use { pointer in
                replay.run { replayFn, proofFn, user in
                    var out: UnsafeMutablePointer<CChar>? = nil
                    var count = 0
                    let code = call(
                        pointer, b[0].text, b[0].count, b[1].text, b[1].count, b[2].base, b[2].count,
                        replayFn, proofFn, user, &out, &count)
                    return Bridge.result(code, Bridge.text(out, count: count))
                }
            }
        }.get()
        return try Bridge.decode(text)
    }
}
