package com.cipherbird.cb2;

/**
 * The public half of a kcb2.seal recipient pair, the key a local key is
 * sealed to. Close it to release the native key; every method after
 * close throws IllegalStateException.
 */
public final class RecipientPublicKey implements AutoCloseable {
    private long handle;

    private RecipientPublicKey(long handle) {
        this.handle = handle;
    }

    static RecipientPublicKey adopt(long handle) {
        return new RecipientPublicKey(handle);
    }

    /** A recipient public key from its raw bytes. */
    public static RecipientPublicKey fromBytes(byte[] bytes) {
        return new RecipientPublicKey(Native.recipientPublicKeyFromBytes(bytes));
    }

    /** A recipient public key from its kcb2.recipient PASERK text. */
    public static RecipientPublicKey fromPaserk(String text) {
        return new RecipientPublicKey(Native.recipientPublicKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    long handle() {
        if (handle == 0) {
            throw new IllegalStateException("RecipientPublicKey is closed");
        }
        return handle;
    }

    /** The kcb2.recipient PASERK text. */
    public String toPaserk() {
        return Text.string(Native.recipientPublicKeyToPaserk(handle()));
    }

    /** The kcb2.rid identifier of this key. */
    public String paserkId() {
        return Text.string(Native.recipientPublicKeyPaserkId(handle()));
    }

    @Override
    public void close() {
        if (handle != 0) {
            Native.recipientPublicKeyFree(handle);
            handle = 0;
        }
    }
}
