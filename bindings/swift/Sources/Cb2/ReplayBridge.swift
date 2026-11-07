import CCb2

/// Carries the replay checks of a `Rules` value across the C boundary. The
/// C callbacks are the two trampolines below and the user pointer is this
/// object, unretained and kept alive by `run` for the duration of the call.
/// The library calls back synchronously on the calling thread.
final class ReplayBridge {
    let replay: Rules.ReplayCheck?
    let proofReplay: Rules.ReplayCheck?

    init(_ rules: Rules) {
        replay = rules.replay
        proofReplay = rules.proofReplay
    }

    func run<T>(_ body: (cb2_replay_fn?, cb2_replay_fn?, UnsafeMutableRawPointer) -> T) -> T {
        withExtendedLifetime(self) {
            body(
                replay == nil ? nil : replayTrampoline,
                proofReplay == nil ? nil : proofReplayTrampoline,
                Unmanaged.passUnretained(self).toOpaque()
            )
        }
    }

    fileprivate func answer(_ jti: UnsafePointer<CChar>?, _ count: Int, proof: Bool) -> Int32 {
        guard let check = proof ? proofReplay : replay else {
            return 0
        }
        let id = String(decoding: UnsafeRawBufferPointer(start: jti, count: jti == nil ? 0 : count), as: UTF8.self)
        do {
            return try check(id) ? 1 : 0
        } catch {
            return 0
        }
    }
}

private func bridge(_ user: UnsafeMutableRawPointer?) -> ReplayBridge? {
    user.map { Unmanaged<ReplayBridge>.fromOpaque($0).takeUnretainedValue() }
}

private let replayTrampoline: cb2_replay_fn = { user, jti, count in
    bridge(user)?.answer(jti, count, proof: false) ?? 0
}

private let proofReplayTrampoline: cb2_replay_fn = { user, jti, count in
    bridge(user)?.answer(jti, count, proof: true) ?? 0
}
