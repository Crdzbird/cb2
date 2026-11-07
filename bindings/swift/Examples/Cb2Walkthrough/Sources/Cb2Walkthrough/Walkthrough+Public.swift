import Cb2
import Foundation

extension Walkthrough {
    func publicTokens(_ log: inout StepLog) throws(Cb2Error) {
        let section = "cb2.public"
        let signer = try SecretKey.generate()
        let verifier = try PublicKey(paserk: try signer.publicKey().toPaserk())
        let token = try Token.sign(claims, key: signer)
        log.accept(section, "Sign a cb2.public token (Ed25519 + ML-DSA-65)") { preview(token) }
        log.accept(section, "Verify it with the public key") { () throws(Cb2Error) in
            summary(try Token.verify(token, key: verifier, rules: rules))
        }
        let stranger = try SecretKey.generate().publicKey()
        log.refuse(section, "Verify it with another public key", expected: .invalid) { () throws(Cb2Error) in
            _ = try Token.verify(token, key: stranger, rules: rules)
        }

        let client = try SecretKey.generate()
        let key = try LocalKey.generate()
        var bound = claims
        bound["cnf"] = .string(try client.publicKey().toPaserk())
        let access = try Token.seal(bound, key: key)
        let proof = try Holder.prove(
            client: client, request: resource, accessToken: access, jti: UUID().uuidString, now: now)
        log.accept("Holder proof, public mode", "Prove possession of the client pair") { preview(proof) }
        var presented = rules
        presented.proof = proof
        presented.request = resource
        presented.proofReplay = { _ in true }
        log.accept("Holder proof, public mode", "Present the token with the proof") { () throws(Cb2Error) in
            summary(try Token.open(access, key: key, rules: presented))
        }
    }

    func sealing(_ log: inout StepLog) throws(Cb2Error) {
        let section = "kcb2.seal"
        let recipient = try RecipientKey.generate()
        let key = try LocalKey.generate()
        let sealed = try Seal.seal(key, to: try recipient.publicKey())
        log.accept(section, "Seal a local key to a recipient (X-Wing)") { preview(sealed) }
        log.accept(section, "Unseal it with the recipient pair") { () throws(Cb2Error) in
            let back = try Seal.unseal(sealed, by: recipient)
            return try back.paserkId == key.paserkId ? "same key: \(try key.paserkId)" : "a different key"
        }
        log.refuse(section, "Unseal it with another pair", expected: .invalid) { () throws(Cb2Error) in
            _ = try Seal.unseal(sealed, by: try RecipientKey.generate())
        }
    }
}
