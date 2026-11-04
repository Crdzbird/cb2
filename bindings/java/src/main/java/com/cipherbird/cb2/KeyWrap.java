package com.cipherbird.cb2;

/** Key wrapping: a local key wrapped by another local key as kcb2.local-wrap text. */
public final class KeyWrap {
    private KeyWrap() {
    }

    /** Wraps key under wrapping. */
    public static String wrap(LocalKey wrapping, LocalKey key) {
        return Text.string(Native.wrap(wrapping.handle(), key.handle()));
    }

    /** Unwraps text under wrapping into a new key the caller closes. */
    public static LocalKey unwrap(String text, LocalKey wrapping) {
        return LocalKey.adopt(Native.unwrap(Text.utf8(Text.required(text, "text")), wrapping.handle()));
    }
}
