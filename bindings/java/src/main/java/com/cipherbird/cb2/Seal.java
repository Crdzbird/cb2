package com.cipherbird.cb2;

/** Key sealing: a local key sealed to a recipient's public key as kcb2.seal text. */
public final class Seal {
    private Seal() {
    }

    /** Seals key to the recipient to. */
    public static String seal(RecipientPublicKey to, LocalKey key) {
        return Text.string(Native.seal(to.handle(), key.handle()));
    }

    /** Unseals text with the recipient pair by into a new key the caller closes. */
    public static LocalKey unseal(String text, RecipientKey by) {
        return LocalKey.adopt(Native.unseal(Text.utf8(Text.required(text, "text")), by.handle()));
    }
}
