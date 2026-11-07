package com.cipherbird.cb2;

/**
 * The secret half of a cb2.public signing pair (Ed25519 and ML-DSA-65),
 * also the client pair of public-mode holder proofs.
 *
 * <p>A key may be used from several threads at once. Close it to release
 * and wipe the native key; every method after close throws
 * IllegalStateException. A key that is never closed is released once it
 * becomes unreachable, but closing it promptly is the contract.
 */
public final class SecretKey implements AutoCloseable {
    final NativeHandle handle;

    private SecretKey(long handle) {
        this.handle = NativeHandle.of(this, "SecretKey", handle, Native::secretKeyFree);
    }

    /**
     * A fresh signing pair.
     *
     * @return the new pair, which the caller closes
     * @throws Cb2Exception with {@link Code#UNAVAILABLE} when the build has
     *     no cb2.public
     */
    public static SecretKey generate() {
        return new SecretKey(Native.secretKeyGenerate());
    }

    /**
     * A pair from its raw secret bytes. The bytes are copied; the caller may
     * wipe the array afterwards.
     *
     * @param bytes the secret key bytes
     * @return the pair, which the caller closes
     * @throws Cb2Exception when the bytes are not a secret key
     */
    public static SecretKey fromBytes(byte[] bytes) {
        return new SecretKey(Native.secretKeyFromBytes(Text.required(bytes, "bytes")));
    }

    /**
     * A pair from its kcb2.secret PASERK text.
     *
     * @param text the PASERK text
     * @return the pair, which the caller closes
     * @throws Cb2Exception when the text is not a kcb2.secret key
     */
    public static SecretKey fromPaserk(String text) {
        return new SecretKey(Native.secretKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    /**
     * The kcb2.secret PASERK text of this pair. It is key material: handle
     * it with care.
     *
     * @return the PASERK text
     */
    public String toPaserk() {
        return Text.string(handle.use(Native::secretKeyToPaserk));
    }

    /**
     * The public half of this pair.
     *
     * @return a new public key, which the caller closes
     */
    public PublicKey publicKey() {
        return PublicKey.adopt(handle.use(Native::secretKeyPublicKey));
    }

    /**
     * The key id bound into the footers of the tokens this pair signs.
     *
     * @return the key id, or null when none is set
     */
    public String keyId() {
        return Text.string(handle.use(Native::secretKeyKeyId));
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
        handle.change(h -> Native.secretKeySetKeyId(h, bytes));
    }

    /** Clears the key id so tokens carry none. */
    public void clearKeyId() {
        handle.change(Native::secretKeyClearKeyId);
    }

    /** Releases and wipes the native key; closing twice does nothing. */
    @Override
    public void close() {
        handle.close();
    }
}
