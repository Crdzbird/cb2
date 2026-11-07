package com.cipherbird.cb2;

/**
 * Raw cb2.public tokens: any bytes as the message, signed by a
 * {@link SecretKey} and verified by its {@link PublicKey}, with an
 * optional footer and implicit assertion. A null footer or implicit means
 * none. For claims checked against rules use {@link Token}.
 */
public final class Public {
    private Public() {
    }

    /**
     * Signs message with key, no footer and no implicit assertion.
     *
     * @param key the signing pair
     * @param message the bytes to sign
     * @return the cb2.public token
     */
    public static String sign(SecretKey key, byte[] message) {
        return sign(key, message, null, null);
    }

    /**
     * Signs message with key and a footer.
     *
     * @param key the signing pair
     * @param message the bytes to sign
     * @param footer the footer, or null for none
     * @return the cb2.public token
     */
    public static String sign(SecretKey key, byte[] message, byte[] footer) {
        return sign(key, message, footer, null);
    }

    /**
     * Signs message with key, a footer and an implicit assertion.
     *
     * @param key the signing pair
     * @param message the bytes to sign
     * @param footer the footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @return the cb2.public token
     */
    public static String sign(SecretKey key, byte[] message, byte[] footer, byte[] implicit) {
        Text.required(message, "message");
        return Text.string(Text.required(key, "key").handle.use(h -> Native.publicSign(h, message, footer, implicit)));
    }

    /**
     * Verifies token with key, expecting no footer and no implicit
     * assertion.
     *
     * @param key the public key
     * @param token the cb2.public token
     * @return the signed message
     * @throws Cb2Exception with {@link Code#INVALID} when the signatures do
     *     not verify
     */
    public static byte[] verify(PublicKey key, String token) {
        return verify(key, token, null, null, 0);
    }

    /**
     * Verifies token with key, expecting footer.
     *
     * @param key the public key
     * @param token the cb2.public token
     * @param footer the expected footer, or null for none
     * @return the signed message
     * @throws Cb2Exception with {@link Code#INVALID} when the signatures do
     *     not verify with that footer
     */
    public static byte[] verify(PublicKey key, String token, byte[] footer) {
        return verify(key, token, footer, null, 0);
    }

    /**
     * Verifies token with key, expecting footer and implicit.
     *
     * @param key the public key
     * @param token the cb2.public token
     * @param footer the expected footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @return the signed message
     * @throws Cb2Exception with {@link Code#INVALID} when the signatures do
     *     not verify with that footer and assertion
     */
    public static byte[] verify(PublicKey key, String token, byte[] footer, byte[] implicit) {
        return verify(key, token, footer, implicit, 0);
    }

    /**
     * Verifies token with key with a size limit.
     *
     * @param key the public key
     * @param token the cb2.public token
     * @param footer the expected footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @param maxTokenBytes the largest token accepted; 0 keeps the library
     *     default
     * @return the signed message
     * @throws Cb2Exception with {@link Code#TOO_LARGE} or
     *     {@link Code#INVALID} when the token is refused
     */
    public static byte[] verify(PublicKey key, String token, byte[] footer, byte[] implicit, long maxTokenBytes) {
        byte[] t = Text.utf8(Text.required(token, "token"));
        return Text.required(key, "key").handle.use(h -> Native.publicVerify(h, t, footer, implicit, maxTokenBytes));
    }
}
