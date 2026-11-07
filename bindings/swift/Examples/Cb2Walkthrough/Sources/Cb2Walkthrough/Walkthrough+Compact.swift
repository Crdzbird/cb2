import Cb2
import Foundation

extension Walkthrough {
    func compact(_ log: inout StepLog) throws(Cb2Error) {
        let section = "Compact claims (experimental)"
        let key = try LocalKey.generate()
        let token = try Compact.seal(claims, key: key)
        let full = try Token.seal(claims, key: key)
        log.accept(section, "Issue a cb3.local token") { "\(preview(token)), cb2.local: \(full.utf8.count) bytes" }
        log.accept(section, "Pick the key by the digest in its footer") { () throws(Cb2Error) in
            let digest = try Compact.peekKeyDigest(token)
            return try digest == Compact.keyDigest(key.keyId ?? "") ? "the digest matches the key id" : "no match"
        }
        log.accept(section, "Open it under the rules") { () throws(Cb2Error) in
            summary(try Compact.open(token, key: key, rules: rules))
        }
        log.refuse(section, "Open it as a cb2.local token", expected: .invalid) { () throws(Cb2Error) in
            _ = try Token.open(token, key: key, rules: rules)
        }
        var fraction = claims
        fraction["ratio"] = 1.5
        log.refuse(section, "Issue one with a fractional claim", expected: .argument) { () throws(Cb2Error) in
            _ = try Compact.seal(fraction, key: key)
        }
        guard Library.hasPublic else {
            return
        }
        let signer = try SecretKey.generate()
        let signed = try Compact.sign(claims, key: signer)
        log.accept(section, "Sign a cb3.public token") { preview(signed) }
        log.accept(section, "Verify it with the public key") { () throws(Cb2Error) in
            summary(try Compact.verify(signed, key: try signer.publicKey(), rules: rules))
        }
    }
}
