package com.cipherbird.cb2;

/**
 * The public half of a cb2.public signing pair. Close it to release the
 * native key; every method after close throws IllegalStateException.
 */
public final class PublicKey implements AutoCloseable {
    private long handle;

    private PublicKey(long handle) {
        this.handle = handle;
    }

    static PublicKey adopt(long handle) {
        return new PublicKey(handle);
    }

    /** A public key from its raw bytes. */
    public static PublicKey fromBytes(byte[] bytes) {
        return new PublicKey(Native.publicKeyFromBytes(bytes));
    }

    /** A public key from its kcb2.public PASERK text. */
    public static PublicKey fromPaserk(String text) {
        return new PublicKey(Native.publicKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    long handle() {
        if (handle == 0) {
            throw new IllegalStateException("PublicKey is closed");
        }
        return handle;
    }

    /** The kcb2.public PASERK text. */
    public String toPaserk() {
        return Text.string(Native.publicKeyToPaserk(handle()));
    }

    /** The kcb2.pid identifier of this key. */
    public String paserkId() {
        return Text.string(Native.publicKeyPaserkId(handle()));
    }

    /** The key id bound into token footers, or null when none is set. */
    public String keyId() {
        return Text.string(Native.publicKeyKeyId(handle()));
    }

    /** Sets the key id; identifiers with hidden characters are refused with argument. */
    public void setKeyId(String id) {
        Native.publicKeySetKeyId(handle(), Text.utf8(Text.required(id, "id")));
    }

    /** Clears the key id so tokens carry none. */
    public void clearKeyId() {
        Native.publicKeyClearKeyId(handle());
    }

    @Override
    public void close() {
        if (handle != 0) {
            Native.publicKeyFree(handle);
            handle = 0;
        }
    }
}
