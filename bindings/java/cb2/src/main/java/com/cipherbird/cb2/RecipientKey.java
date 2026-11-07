package com.cipherbird.cb2;

/**
 * The secret half of a kcb2.seal recipient pair (X-Wing), which unseals
 * the local keys sealed to its public half.
 *
 * <p>A key may be used from several threads at once. Close it to release
 * and wipe the native key; every method after close throws
 * IllegalStateException. A key that is never closed is released once it
 * becomes unreachable, but closing it promptly is the contract.
 */
public final class RecipientKey implements AutoCloseable {
    final NativeHandle handle;

    private RecipientKey(long handle) {
        this.handle = NativeHandle.of(this, "RecipientKey", handle, Native::recipientKeyFree);
    }

    /**
     * A fresh recipient pair.
     *
     * @return the new pair, which the caller closes
     * @throws Cb2Exception with {@link Code#UNAVAILABLE} when the build has
     *     no kcb2.seal
     */
    public static RecipientKey generate() {
        return new RecipientKey(Native.recipientKeyGenerate());
    }

    /**
     * A pair from its raw secret bytes. The bytes are copied; the caller may
     * wipe the array afterwards.
     *
     * @param bytes the secret bytes
     * @return the pair, which the caller closes
     * @throws Cb2Exception when the bytes are not a recipient key
     */
    public static RecipientKey fromBytes(byte[] bytes) {
        return new RecipientKey(Native.recipientKeyFromBytes(Text.required(bytes, "bytes")));
    }

    /**
     * A pair from its kcb2.recipient-secret PASERK text.
     *
     * @param text the PASERK text
     * @return the pair, which the caller closes
     * @throws Cb2Exception when the text is not a recipient secret
     */
    public static RecipientKey fromPaserk(String text) {
        return new RecipientKey(Native.recipientKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    /**
     * The kcb2.recipient-secret PASERK text of this pair. It is key
     * material: handle it with care.
     *
     * @return the PASERK text
     */
    public String toPaserk() {
        return Text.string(handle.use(Native::recipientKeyToPaserk));
    }

    /**
     * The public half of this pair, the key others seal to.
     *
     * @return a new recipient public key, which the caller closes
     */
    public RecipientPublicKey publicKey() {
        return RecipientPublicKey.adopt(handle.use(Native::recipientKeyPublicKey));
    }

    /**
     * The kcb2.rid identifier of this pair.
     *
     * @return the identifier
     */
    public String paserkId() {
        return Text.string(handle.use(Native::recipientKeyPaserkId));
    }

    /** Releases and wipes the native key; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
