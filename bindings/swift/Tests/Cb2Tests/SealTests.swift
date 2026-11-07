import Cb2
import Foundation
import Testing

@Suite(.enabled(if: Library.hasSeal, "kcb2.seal is not in this build"))
struct SealTests {
    @Test("a local key seals to a recipient and only that recipient unseals it")
    func aLocalKeySealsToARecipientAndOnlyThatRecipientUnsealsIt() throws {
        let recipient = try RecipientKey.generate()
        let pub = try recipient.publicKey()
        let paserk = try pub.toPaserk()
        #expect(paserk.hasPrefix("kcb2.recipient."))
        #expect(paserk.count == 1637)
        let secret = try recipient.toPaserk()
        #expect(secret.count == 65)
        let restored = try RecipientKey(paserk: secret)

        let key = try LocalKey.generate()
        let sealed = try Seal.seal(key, to: pub)
        #expect(sealed.count == 1632)
        #expect(try Seal.unseal(sealed, by: restored).paserkId == key.paserkId)
        #expect(throws: Cb2Error.invalid) { try Seal.unseal(sealed, by: RecipientKey.generate()) }

        let rid = try pub.paserkId
        #expect(rid.hasPrefix("kcb2.rid."))
        #expect(try restored.paserkId == rid)
        #expect(try RecipientPublicKey(paserk: paserk).paserkId == rid)
    }
}
