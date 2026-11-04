package com.cipherbird.cb2;

/**
 * A refusal by the library: the positive error code of the C ABI and its
 * stable name ("invalid", "expired", "replayed", ...). The constants in
 * {@link Code} name every code.
 */
public final class Cb2Exception extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final int code;
    private final String name;

    public Cb2Exception(int code, String name) {
        super("cb2: " + name + " (" + code + ")");
        this.code = code;
        this.name = name;
    }

    /** The error code, one of the constants in {@link Code}. */
    public int code() {
        return code;
    }

    /** The stable verdict name the library uses for this code. */
    public String name() {
        return name;
    }
}
