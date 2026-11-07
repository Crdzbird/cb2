import Cb2
import Foundation

extension Walkthrough {
    func local(_ log: inout StepLog) throws(Cb2Error) {
        let section = "cb2.local"
        let key = try LocalKey.generate()
        let token = try Token.seal(claims, key: key)
        log.accept(section, "Issue a cb2.local token") { preview(token) }

        let store = ReplayStore()
        var checked = rules
        checked.replay = { store.accept($0) }
        log.accept(section, "Open it under the rules") { () throws(Cb2Error) in
            summary(try Token.open(token, key: key, rules: checked))
        }
        log.refuse(section, "Open the same token again", expected: .replayed) { () throws(Cb2Error) in
            _ = try Token.open(token, key: key, rules: checked)
        }

        var billing = rules
        billing.audience = "billing"
        log.refuse(section, "Open it for another audience", expected: .audienceMismatch) { () throws(Cb2Error) in
            _ = try Token.open(token, key: key, rules: billing)
        }
        var later = rules
        later.now = now + 7200
        log.refuse(section, "Open it two hours later", expected: .expired) { () throws(Cb2Error) in
            _ = try Token.open(token, key: key, rules: later)
        }
        let tampered = String(token.dropLast()) + (token.last == "A" ? "B" : "A")
        log.refuse(section, "Open a tampered copy", expected: .invalid) { () throws(Cb2Error) in
            _ = try Token.open(tampered, key: key, rules: rules)
        }
        let stranger = try LocalKey.generate()
        log.refuse(section, "Open it under another key", expected: .invalid) { () throws(Cb2Error) in
            _ = try Token.open(token, key: stranger, rules: rules)
        }
    }

    func holderLocal(_ log: inout StepLog) throws(Cb2Error) {
        let section = "Holder proof, local mode"
        let key = try LocalKey.generate()
        let proofKey = try LocalKey.generate()
        var bound = claims
        bound["cnf"] = .string(try proofKey.toPaserk())
        let access = try Token.seal(bound, key: key)
        log.refuse(section, "Present the bound token alone", expected: .missingProof) { () throws(Cb2Error) in
            _ = try Token.open(access, key: key, rules: rules)
        }

        let proof = try Holder.proveLocal(
            proofKey: proofKey, request: resource, accessToken: access, jti: UUID().uuidString, now: now)
        log.accept(section, "Prove possession of the proof key") { preview(proof) }

        let store = ReplayStore()
        var presented = rules
        presented.proof = proof
        presented.request = resource
        presented.proofReplay = { store.accept($0) }
        log.accept(section, "Present the token with the proof") { () throws(Cb2Error) in
            summary(try Token.open(access, key: key, rules: presented))
        }
        log.refuse(section, "Replay the same proof", expected: .proofReplayed) { () throws(Cb2Error) in
            _ = try Token.open(access, key: key, rules: presented)
        }
        var other = presented
        other.request = HolderRequest(htm: "DELETE", htu: resource.htu)
        other.proofReplay = { _ in true }
        log.refuse(section, "Present the proof for another request", expected: .proofMismatch) {
            () throws(Cb2Error) in
            _ = try Token.open(access, key: key, rules: other)
        }
    }
}
