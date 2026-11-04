package com.cipherbird.cb2;

/** JSON string quoting for the claims and rules text the bridge builds by hand. */
public final class Json {
    private Json() {
    }

    /** Returns the JSON string literal for s, quotes included. */
    public static String quote(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        quoteTo(sb, s);
        return sb.toString();
    }

    /** Appends the JSON string literal for s, quotes included, to sb. */
    public static void quoteTo(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
