package com.cipherbird.cb2;

/**
 * Raw cb2.local tokens: any bytes as the message, with an optional footer
 * and implicit assertion. A null footer or implicit means none.
 */
public final class Local {
    private Local() {
    }

    /** Seals message under key with no footer and no implicit assertion. */
    public static String seal(LocalKey key, byte[] message) {
        return seal(key, message, null, null);
    }

    /** Seals message under key with a footer and no implicit assertion. */
    public static String seal(LocalKey key, byte[] message, byte[] footer) {
        return seal(key, message, footer, null);
    }

    /** Seals message under key with a footer and an implicit assertion. */
    public static String seal(LocalKey key, byte[] message, byte[] footer, byte[] implicit) {
        return Text.string(Native.localSeal(key.handle(), message, footer, implicit));
    }

    /** Opens token under key with no footer and no implicit assertion. */
    public static byte[] open(LocalKey key, String token) {
        return open(key, token, null, null, 0);
    }

    /** Opens token under key, expecting footer. */
    public static byte[] open(LocalKey key, String token, byte[] footer) {
        return open(key, token, footer, null, 0);
    }

    /** Opens token under key, expecting footer and implicit. */
    public static byte[] open(LocalKey key, String token, byte[] footer, byte[] implicit) {
        return open(key, token, footer, implicit, 0);
    }

    /** Opens token under key; maxTokenBytes of 0 keeps the library default. */
    public static byte[] open(LocalKey key, String token, byte[] footer, byte[] implicit, long maxTokenBytes) {
        return Native.localOpen(key.handle(), Text.utf8(Text.required(token, "token")), footer, implicit, maxTokenBytes);
    }
}
