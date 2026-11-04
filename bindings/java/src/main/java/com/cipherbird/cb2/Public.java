package com.cipherbird.cb2;

/**
 * Raw cb2.public tokens: any bytes as the message, signed by a secret key
 * and verified by its public half. A null footer or implicit means none.
 */
public final class Public {
    private Public() {
    }

    /** Signs message with key, no footer and no implicit assertion. */
    public static String sign(SecretKey key, byte[] message) {
        return sign(key, message, null, null);
    }

    /** Signs message with key and a footer. */
    public static String sign(SecretKey key, byte[] message, byte[] footer) {
        return sign(key, message, footer, null);
    }

    /** Signs message with key, a footer and an implicit assertion. */
    public static String sign(SecretKey key, byte[] message, byte[] footer, byte[] implicit) {
        return Text.string(Native.publicSign(key.handle(), message, footer, implicit));
    }

    /** Verifies token with key, no footer and no implicit assertion. */
    public static byte[] verify(PublicKey key, String token) {
        return verify(key, token, null, null, 0);
    }

    /** Verifies token with key, expecting footer. */
    public static byte[] verify(PublicKey key, String token, byte[] footer) {
        return verify(key, token, footer, null, 0);
    }

    /** Verifies token with key, expecting footer and implicit. */
    public static byte[] verify(PublicKey key, String token, byte[] footer, byte[] implicit) {
        return verify(key, token, footer, implicit, 0);
    }

    /** Verifies token with key; maxTokenBytes of 0 keeps the library default. */
    public static byte[] verify(PublicKey key, String token, byte[] footer, byte[] implicit, long maxTokenBytes) {
        return Native.publicVerify(key.handle(), Text.utf8(Text.required(token, "token")), footer, implicit, maxTokenBytes);
    }
}
