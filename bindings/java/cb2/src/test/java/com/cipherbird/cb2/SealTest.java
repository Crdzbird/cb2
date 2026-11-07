package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.expect;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import org.junit.jupiter.api.Test;

class SealTest {
    @Test
    void sealToARecipient() {
        assumeTrue(Cb2.hasSeal(), "kcb2.seal unavailable in this build");
        try (RecipientKey r = RecipientKey.generate();
                RecipientPublicKey rp = r.publicKey();
                LocalKey k = LocalKey.generate();
                RecipientKey other = RecipientKey.generate()) {
            String rec = rp.toPaserk();
            assertTrue(rec.startsWith("kcb2.recipient."), "recipient paserk prefix");
            assertEquals(1637, rec.length(), "recipient paserk length");
            String secret = r.toPaserk();
            assertEquals(65, secret.length(), "recipient secret length");
            try (RecipientKey r2 = RecipientKey.fromPaserk(secret);
                    RecipientPublicKey rp2 = RecipientPublicKey.fromPaserk(rec)) {
                String sealed = Seal.seal(rp2, k);
                assertEquals(1632, sealed.length(), "sealed length");
                try (LocalKey back = Seal.unseal(sealed, r2)) {
                    assertEquals(k.paserkId(), back.paserkId(), "unsealed key is the same key");
                }
                expect(Code.INVALID, "unseal by another recipient", () -> Seal.unseal(sealed, other));
                assertEquals(rp.paserkId(), r2.paserkId(), "recipient ids");
                assertTrue(rp.paserkId().startsWith("kcb2.rid."), "recipient id prefix");
            }
        }
    }
}
