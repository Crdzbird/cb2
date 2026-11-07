package com.cipherbird.cb2;

/** Key sealing: a local key sealed to a recipient's public key as kcb2.seal text. */
public final class Seal {
    private Seal() {
    }

    /**
     * Seals key to the recipient to.
     *
     * @param to the recipient's public key
     * @param key the key to seal
     * @return the kcb2.seal text
     * @throws Cb2Exception with {@link Code#UNAVAILABLE} when the build has
     *     no kcb2.seal
     */
    public static String seal(RecipientPublicKey to, LocalKey key) {
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(Text.required(to, "to").handle.use(r -> k.use(h -> Native.seal(r, h))));
    }

    /**
     * Unseals text with the recipient pair by.
     *
     * @param text the kcb2.seal text
     * @param by the recipient pair
     * @return the unsealed key, which the caller closes
     * @throws Cb2Exception with {@link Code#INVALID} when text was not
     *     sealed to by
     */
    public static LocalKey unseal(String text, RecipientKey by) {
        byte[] t = Text.utf8(Text.required(text, "text"));
        return LocalKey.adopt(Text.required(by, "by").handle.use(r -> Native.unseal(t, r)));
    }
}
