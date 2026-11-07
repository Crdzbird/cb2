package com.cipherbird.cb2;

import java.util.List;

/** A JSON object written member by member; absent (null) values are left out. */
final class JsonObject {
    private final StringBuilder sb = new StringBuilder("{");
    private boolean first = true;

    private void key(String name) {
        if (!first) {
            sb.append(',');
        }
        first = false;
        Json.quoteTo(sb, name);
        sb.append(':');
    }

    void number(String name, Long value) {
        if (value == null) {
            return;
        }
        key(name);
        sb.append(value.longValue());
    }

    void bool(String name, Boolean value) {
        if (value == null) {
            return;
        }
        key(name);
        sb.append(value.booleanValue());
    }

    void string(String name, String value) {
        if (value == null) {
            return;
        }
        key(name);
        Json.quoteTo(sb, value);
    }

    void strings(String name, List<String> values) {
        if (values == null) {
            return;
        }
        key(name);
        sb.append('[');
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                sb.append(',');
            }
            Json.quoteTo(sb, values.get(i));
        }
        sb.append(']');
    }

    void raw(String name, String json) {
        if (json == null) {
            return;
        }
        key(name);
        sb.append(json);
    }

    @Override
    public String toString() {
        return sb + "}";
    }
}
