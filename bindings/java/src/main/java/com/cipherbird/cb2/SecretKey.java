package com.cipherbird.cb2;

/**
 * The secret half of a cb2.public signing pair. Close it to release the
 * native key; every method after close throws IllegalStateException.
 */
public final class SecretKey implements AutoCloseable {
    private long handle;

    private SecretKey(long handle) {
        this.handle = handle;
    }

    /** A fresh signing pair; unavailable when the build has no cb2.public. */
    public static SecretKey generate() {
        return new SecretKey(Native.secretKeyGenerate());
    }

    /** A pair from its raw secret bytes. */
    public static SecretKey fromBytes(byte[] bytes) {
        return new SecretKey(Native.secretKeyFromBytes(bytes));
    }

    /** A pair from its kcb2.secret PASERK text. */
    public static SecretKey fromPaserk(String text) {
        return new SecretKey(Native.secretKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    long handle() {
        if (handle == 0) {
            throw new IllegalStateException("SecretKey is closed");
        }
        return handle;
    }

    /** The kcb2.secret PASERK text: key material, handle with care. */
    public String toPaserk() {
        return Text.string(Native.secretKeyToPaserk(handle()));
    }

    /** The public half, as a new key the caller closes. */
    public PublicKey publicKey() {
        return PublicKey.adopt(Native.secretKeyPublicKey(handle()));
    }

    /** The key id bound into token footers, or null when none is set. */
    public String keyId() {
        return Text.string(Native.secretKeyKeyId(handle()));
    }

    /** Sets the key id; identifiers with hidden characters are refused with argument. */
    public void setKeyId(String id) {
        Native.secretKeySetKeyId(handle(), Text.utf8(Text.required(id, "id")));
    }

    /** Clears the key id so tokens carry none. */
    public void clearKeyId() {
        Native.secretKeyClearKeyId(handle());
    }

    @Override
    public void close() {
        if (handle != 0) {
            Native.secretKeyFree(handle);
            handle = 0;
        }
    }
}
