import CCb2

/// Carries the replay closures of a Rules value across the C boundary: the
/// C callbacks are the two trampolines below and the user pointer is this
/// object, unretained, kept alive for the duration of the call by run.
final class ReplayBridge {
    let replay: ((String) throws -> Bool)?
    let proofReplay: ((String) throws -> Bool)?

    init(replay: ((String) throws -> Bool)?, proofReplay: ((String) throws -> Bool)?) {
        self.replay = replay
        self.proofReplay = proofReplay
    }

    func run<T>(_ body: (cb2_replay_fn?, cb2_replay_fn?, UnsafeMutableRawPointer?) throws -> T) rethrows -> T {
        try withExtendedLifetime(self) {
            let replayFn: cb2_replay_fn? = replay == nil ? nil : replayTrampoline
            let proofFn: cb2_replay_fn? = proofReplay == nil ? nil : proofReplayTrampoline
            return try body(replayFn, proofFn, Unmanaged.passUnretained(self).toOpaque())
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
