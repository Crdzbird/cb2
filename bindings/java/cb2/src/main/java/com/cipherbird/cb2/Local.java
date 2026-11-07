package com.cipherbird.cb2;

/**
 * Raw cb2.local tokens: any bytes as the message, encrypted and
 * authenticated under a {@link LocalKey}, with an optional footer (sent in
 * clear, authenticated) and implicit assertion (authenticated, never
 * sent). A null footer or implicit means none. For claims checked against
 * rules use {@link Token}.
 */
public final class Local {
    private Local() {
    }

    /**
     * Seals message under key with no footer and no implicit assertion.
     *
     * @param key the key
     * @param message the bytes to seal
     * @return the cb2.local token
     */
    public static String seal(LocalKey key, byte[] message) {
        return seal(key, message, null, null);
    }

    /**
     * Seals message under key with a footer and no implicit assertion.
     *
     * @param key the key
     * @param message the bytes to seal
     * @param footer the footer, or null for none
     * @return the cb2.local token
     */
    public static String seal(LocalKey key, byte[] message, byte[] footer) {
        return seal(key, message, footer, null);
    }

    /**
     * Seals message under key with a footer and an implicit assertion.
     *
     * @param key the key
     * @param message the bytes to seal
     * @param footer the footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @return the cb2.local token
     */
    public static String seal(LocalKey key, byte[] message, byte[] footer, byte[] implicit) {
        Text.required(message, "message");
        return Text.string(Text.required(key, "key").handle.use(h -> Native.localSeal(h, message, footer, implicit)));
    }

    /**
     * Opens token under key, expecting no footer and no implicit assertion.
     *
     * @param key the key
     * @param token the cb2.local token
     * @return the message
     * @throws Cb2Exception with {@link Code#INVALID} when the token is not
     *     authentic under key
     */
    public static byte[] open(LocalKey key, String token) {
        return open(key, token, null, null, 0);
    }

    /**
     * Opens token under key, expecting footer.
     *
     * @param key the key
     * @param token the cb2.local token
     * @param footer the expected footer, or null for none
     * @return the message
     * @throws Cb2Exception with {@link Code#INVALID} when the token is not
     *     authentic under key with that footer
     */
    public static byte[] open(LocalKey key, String token, byte[] footer) {
        return open(key, token, footer, null, 0);
    }

    /**
     * Opens token under key, expecting footer and implicit.
     *
     * @param key the key
     * @param token the cb2.local token
     * @param footer the expected footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @return the message
     * @throws Cb2Exception with {@link Code#INVALID} when the token is not
     *     authentic under key with that footer and assertion
     */
    public static byte[] open(LocalKey key, String token, byte[] footer, byte[] implicit) {
        return open(key, token, footer, implicit, 0);
    }

    /**
     * Opens token under key with a size limit.
     *
     * @param key the key
     * @param token the cb2.local token
     * @param footer the expected footer, or null for none
     * @param implicit the implicit assertion, or null for none
     * @param maxTokenBytes the largest token accepted; 0 keeps the library
     *     default
     * @return the message
     * @throws Cb2Exception with {@link Code#TOO_LARGE} or
     *     {@link Code#INVALID} when the token is refused
     */
    public static byte[] open(LocalKey key, String token, byte[] footer, byte[] implicit, long maxTokenBytes) {
        byte[] t = Text.utf8(Text.required(token, "token"));
        return Text.required(key, "key").handle.use(h -> Native.localOpen(h, t, footer, implicit, maxTokenBytes));
    }
}
