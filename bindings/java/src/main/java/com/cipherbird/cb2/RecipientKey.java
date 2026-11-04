package com.cipherbird.cb2;

/**
 * The secret half of a kcb2.seal recipient pair. Close it to release the
 * native key; every method after close throws IllegalStateException.
 */
public final class RecipientKey implements AutoCloseable {
    private long handle;

    private RecipientKey(long handle) {
        this.handle = handle;
    }

    /** A fresh recipient pair; unavailable when the build has no kcb2.seal. */
    public static RecipientKey generate() {
        return new RecipientKey(Native.recipientKeyGenerate());
    }

    /** A pair from its raw secret bytes. */
    public static RecipientKey fromBytes(byte[] bytes) {
        return new RecipientKey(Native.recipientKeyFromBytes(bytes));
    }

    /** A pair from its kcb2.recipient-secret PASERK text. */
    public static RecipientKey fromPaserk(String text) {
        return new RecipientKey(Native.recipientKeyFromPaserk(Text.utf8(Text.required(text, "text"))));
    }

    long handle() {
        if (handle == 0) {
            throw new IllegalStateException("RecipientKey is closed");
        }
        return handle;
    }

    /** The kcb2.recipient-secret PASERK text: key material, handle with care. */
    public String toPaserk() {
        return Text.string(Native.recipientKeyToPaserk(handle()));
    }

    /** The public half, as a new key the caller closes. */
    public RecipientPublicKey publicKey() {
        return RecipientPublicKey.adopt(Native.recipientKeyPublicKey(handle()));
    }

    /** The kcb2.rid identifier of this pair. */
    public String paserkId() {
        return Text.string(Native.recipientKeyPaserkId(handle()));
    }

    @Override
    public void close() {
        if (handle != 0) {
            Native.recipientKeyFree(handle);
            handle = 0;
        }
    }
}
