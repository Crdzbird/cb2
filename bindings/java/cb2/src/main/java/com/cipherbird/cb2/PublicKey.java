package com.cipherbird.cb2;

/**
 * The public half of a cb2.public signing pair: verifies tokens, and as
 * the cnf of a bound token names the client that must prove possession.
 *
 * <p>A key may be used from several threads at once. Close it to release
 * the native key; every method after close throws IllegalStateException.
 * A key that is never closed is released once it becomes unreachable.
 */
public final class PublicKey implements AutoCloseable {
    final NativeHandle handle;

    private PublicKey(long handle) {
        this.handle = NativeHandle.of(this, "PublicKey", handle, Native::publicKeyFree);
    }

    static PublicKey adopt(long handle) {
        return new PublicKey(handle);
    }

    /**
     * A public key from its raw bytes.
     *
     * @param bytes the public key bytes
     * @return the key, which the caller closes
     * @throws Cb2Exception when the bytes are not a public key
     */
    public static PublicKey fromBytes(byte[] bytes) {
        return new PublicKey(Native.publicKeyFromBytes(Text.required(bytes, "bytes")));
    }

    /**
     * A public key from its kcb2.public PASERK text.
     *
     * @param text the PASERK text
     * @return the key, which the caller closes
     * @throws Cb2Exception when the text is not a kcb2.public key
     */
    public static PublicKey fromPaserk(String text) {
        return new PublicKey(Native.publicKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    /**
     * The kcb2.public PASERK text of this key.
     *
     * @return the PASERK text
     */
    public String toPaserk() {
        return Text.string(handle.use(Native::publicKeyToPaserk));
    }

    /**
     * The kcb2.pid identifier of this key, the default key id.
     *
     * @return the identifier
     */
    public String paserkId() {
        return Text.string(handle.use(Native::publicKeyPaserkId));
    }

    /**
     * The key id this key expects in token footers.
     *
     * @return the key id, or null when none is set
     */
    public String keyId() {
        return Text.string(handle.use(Native::publicKeyKeyId));
    }

    /**
     * Sets the key id this key expects in token footers.
     *
     * @param id the key id
     * @throws Cb2Exception with {@link Code#ARGUMENT} for an identifier with
     *     hidden characters
     */
    public void setKeyId(String id) {
        byte[] bytes = Text.utf8(Text.required(id, "id"));
        handle.change(h -> Native.publicKeySetKeyId(h, bytes));
    }

    /** Clears the key id. */
    public void clearKeyId() {
        handle.change(Native::publicKeyClearKeyId);
    }

    /** Releases the native key; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
