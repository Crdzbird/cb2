package com.cipherbird.cb2;

/**
 * A symmetric key for cb2.local tokens. Close it to release the native
 * key; every method after close throws IllegalStateException.
 */
public final class LocalKey implements AutoCloseable {
    private long handle;

    private LocalKey(long handle) {
        this.handle = handle;
    }

    static LocalKey adopt(long handle) {
        return new LocalKey(handle);
    }

    /** A fresh random key. */
    public static LocalKey generate() {
        return new LocalKey(Native.localKeyGenerate());
    }

    /** A key from its 32 raw bytes; weak material is refused with argument. */
    public static LocalKey fromBytes(byte[] bytes) {
        return new LocalKey(Native.localKeyFromBytes(bytes));
    }

    /** A key from its kcb2.local PASERK text. */
    public static LocalKey fromPaserk(String text) {
        return new LocalKey(Native.localKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    long handle() {
        if (handle == 0) {
            throw new IllegalStateException("LocalKey is closed");
        }
        return handle;
    }

    /** The kcb2.local PASERK text: key material, handle with care. */
    public String toPaserk() {
        return Text.string(Native.localKeyToPaserk(handle()));
    }

    /** The kcb2.lid identifier of this key. */
    public String paserkId() {
        return Text.string(Native.localKeyPaserkId(handle()));
    }

    /** The key id bound into token footers, or null when none is set. */
    public String keyId() {
        return Text.string(Native.localKeyKeyId(handle()));
    }

    /** Sets the key id; identifiers with hidden characters are refused with argument. */
    public void setKeyId(String id) {
        Native.localKeySetKeyId(handle(), Text.utf8(Text.required(id, "id")));
    }

    /** Clears the key id so tokens carry none. */
    public void clearKeyId() {
        Native.localKeyClearKeyId(handle());
    }

    @Override
    public void close() {
        if (handle != 0) {
            Native.localKeyFree(handle);
            handle = 0;
        }
    }
}
