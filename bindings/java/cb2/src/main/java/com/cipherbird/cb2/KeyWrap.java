package com.cipherbird.cb2;

/** Key wrapping: a local key encrypted under another local key as kcb2.local-wrap text. */
public final class KeyWrap {
    private KeyWrap() {
    }

    /**
     * Wraps key under wrapping.
     *
     * @param wrapping the wrapping key
     * @param key the key to wrap
     * @return the kcb2.local-wrap text
     */
    public static String wrap(LocalKey wrapping, LocalKey key) {
        NativeHandle k = Text.required(key, "key").handle;
        return Text.string(Text.required(wrapping, "wrapping").handle.use(
                w -> k.use(h -> Native.wrap(w, h))));
    }

    /**
     * Unwraps text under wrapping.
     *
     * @param text the kcb2.local-wrap text
     * @param wrapping the wrapping key
     * @return the unwrapped key, which the caller closes
     * @throws Cb2Exception with {@link Code#INVALID} when text was not
     *     wrapped under wrapping
     */
    public static LocalKey unwrap(String text, LocalKey wrapping) {
        byte[] t = Text.utf8(Text.required(text, "text"));
        return LocalKey.adopt(Text.required(wrapping, "wrapping").handle.use(w -> Native.unwrap(t, w)));
    }
}
