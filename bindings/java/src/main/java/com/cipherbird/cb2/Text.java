package com.cipherbird.cb2;

import java.nio.charset.StandardCharsets;

/** UTF-8 conversions between the Java strings and the byte arrays the glue takes and returns. */
final class Text {
    private Text() {
    }

    static byte[] utf8(String s) {
        if (s == null) {
            return null;
        }
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String string(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static String required(String value, String what) {
        if (value == null) {
            throw new IllegalArgumentException(what + " must not be null");
        }
        return value;
    }
}
