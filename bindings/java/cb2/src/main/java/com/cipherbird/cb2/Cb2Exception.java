package com.cipherbird.cb2;

/**
 * A refusal by the library: the positive error code of the C ABI and its
 * stable name ({@code "invalid"}, {@code "expired"}, {@code "replayed"},
 * ...). The constants in {@link Code} name every code. The message is
 * {@code "cb2: <name> (<code>)"}.
 */
public final class Cb2Exception extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** The error code. */
    private final int code;

    /** The stable name of the code. */
    private final String name;

    /**
     * A refusal with the given code and name; the glue throws these.
     *
     * @param code the error code
     * @param name the stable name of the code
     */
    public Cb2Exception(int code, String name) {
        super("cb2: " + name + " (" + code + ")");
        this.code = code;
        this.name = name;
    }

    /**
     * The error code.
     *
     * @return one of the constants in {@link Code}
     */
    public int code() {
        return code;
    }

    /**
     * The stable verdict name the library uses for this code.
     *
     * @return the name, such as {@code "replayed"}
     */
    public String name() {
        return name;
    }
}
