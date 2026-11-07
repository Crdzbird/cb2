package com.cipherbird.cb2;

/**
 * The public half of a kcb2.seal recipient pair, the key a local key is
 * sealed to.
 *
 * <p>A key may be used from several threads at once. Close it to release
 * the native key; every method after close throws IllegalStateException.
 * A key that is never closed is released once it becomes unreachable.
 */
public final class RecipientPublicKey implements AutoCloseable {
    final NativeHandle handle;

    private RecipientPublicKey(long handle) {
        this.handle = NativeHandle.of(this, "RecipientPublicKey", handle, Native::recipientPublicKeyFree);
    }

    static RecipientPublicKey adopt(long handle) {
        return new RecipientPublicKey(handle);
    }

    /**
     * A recipient public key from its raw bytes.
     *
     * @param bytes the public key bytes
     * @return the key, which the caller closes
     * @throws Cb2Exception when the bytes are not a recipient public key
     */
    public static RecipientPublicKey fromBytes(byte[] bytes) {
        return new RecipientPublicKey(Native.recipientPublicKeyFromBytes(Text.required(bytes, "bytes")));
    }

    /**
     * A recipient public key from its kcb2.recipient PASERK text.
     *
     * @param text the PASERK text
     * @return the key, which the caller closes
     * @throws Cb2Exception when the text is not a kcb2.recipient key
     */
    public static RecipientPublicKey fromPaserk(String text) {
        return new RecipientPublicKey(Native.recipientPublicKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    /**
     * The kcb2.recipient PASERK text of this key.
     *
     * @return the PASERK text
     */
    public String toPaserk() {
        return Text.string(handle.use(Native::recipientPublicKeyToPaserk));
    }

    /**
     * The kcb2.rid identifier of this key, equal to that of its pair.
     *
     * @return the identifier
     */
    public String paserkId() {
        return Text.string(handle.use(Native::recipientPublicKeyPaserkId));
    }

    /** Releases the native key; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
