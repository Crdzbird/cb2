package com.cipherbird.cb2;

/**
 * A symmetric key for cb2.local tokens, also used as a wrapping key and as
 * the kcb2.local proof key of a bound cb2.local token.
 *
 * <p>A key may be used from several threads at once. Close it to release
 * and wipe the native key; every method after close throws
 * IllegalStateException. A key that is never closed is released once it
 * becomes unreachable, but closing it promptly is the contract.
 */
public final class LocalKey implements AutoCloseable {
    final NativeHandle handle;

    private LocalKey(long handle) {
        this.handle = NativeHandle.of(this, "LocalKey", handle, Native::localKeyFree);
    }

    static LocalKey adopt(long handle) {
        return new LocalKey(handle);
    }

    /**
     * A fresh random key.
     *
     * @return the new key, which the caller closes
     */
    public static LocalKey generate() {
        return new LocalKey(Native.localKeyGenerate());
    }

    /**
     * A key from its 32 raw bytes. The bytes are copied; the caller may
     * wipe the array afterwards.
     *
     * @param bytes the 32 key bytes
     * @return the key, which the caller closes
     * @throws Cb2Exception with {@link Code#ARGUMENT} for the wrong length or
     *     weak material
     */
    public static LocalKey fromBytes(byte[] bytes) {
        return new LocalKey(Native.localKeyFromBytes(Text.required(bytes, "bytes")));
    }

    /**
     * A key from its kcb2.local PASERK text.
     *
     * @param text the PASERK text
     * @return the key, which the caller closes
     * @throws Cb2Exception when the text is not a kcb2.local key
     */
    public static LocalKey fromPaserk(String text) {
        return new LocalKey(Native.localKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    /**
     * The kcb2.local PASERK text of this key. It is key material: handle
     * it with care.
     *
     * @return the PASERK text
     */
    public String toPaserk() {
        return Text.string(handle.use(Native::localKeyToPaserk));
    }

    /**
     * The kcb2.lid identifier of this key, the default key id.
     *
     * @return the identifier
     */
    public String paserkId() {
        return Text.string(handle.use(Native::localKeyPaserkId));
    }

    /**
     * The key id bound into the footers of the tokens this key seals.
     *
     * @return the key id, or null when none is set
     */
    public String keyId() {
        return Text.string(handle.use(Native::localKeyKeyId));
    }

    /**
     * Sets the key id bound into token footers.
     *
     * @param id the key id
     * @throws Cb2Exception with {@link Code#ARGUMENT} for an identifier with
     *     hidden characters
     */
    public void setKeyId(String id) {
        byte[] bytes = Text.utf8(Text.required(id, "id"));
        handle.change(h -> Native.localKeySetKeyId(h, bytes));
    }

    /** Clears the key id so tokens carry none. */
    public void clearKeyId() {
        handle.change(Native::localKeyClearKeyId);
    }

    /** Releases and wipes the native key; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
