package com.cipherbird.cb2;

/**
 * The cb2 library: loads the JNI glue once and answers what the build
 * offers.
 *
 * <p>The glue is found in this order, first match wins: the file named by
 * the system property {@code cb2.jni.library}; the native libraries this
 * jar carries for the running platform under
 * {@code com/cipherbird/cb2/native/<os>-<arch>/} (skipped when
 * {@code cb2.jni.bundled} is {@code false}), extracted into a private
 * temporary directory under {@code cb2.jni.tmpdir} or java.io.tmpdir and
 * deleted once loaded; and {@code System.loadLibrary("cb2_jni")} from
 * java.library.path.
 */
public final class Cb2 {
    private static boolean loaded;

    private Cb2() {
    }

    /**
     * Loads the JNI glue. Every other class calls this before its first
     * native call, so an explicit call is only needed to fail early.
     *
     * @throws UnsatisfiedLinkError when no source yields a loadable glue
     */
    public static synchronized void load() {
        if (loaded) {
            return;
        }
        NativeLoader.load();
        loaded = true;
    }

    /**
     * The version of the native library.
     *
     * @return the version string, such as {@code "0.1.0"}
     */
    public static String version() {
        return Native.version();
    }

    /**
     * Whether cb2.public (signing, and holder proofs by a signing pair) is
     * available in this build.
     *
     * @return true when the native library was built with cb2.public
     */
    public static boolean hasPublic() {
        return Native.hasPublic();
    }

    /**
     * Whether kcb2.seal (sealing a key to a recipient) is available in this
     * build.
     *
     * @return true when the native library was built with kcb2.seal
     */
    public static boolean hasSeal() {
        return Native.hasSeal();
    }

    /**
     * The stable name of an error code.
     *
     * @param code an error code, one of the constants in {@link Code}
     * @return the name, {@code "ok"} for 0 and {@code "unknown"} for codes
     *     the library does not use
     */
    public static String errorName(int code) {
        return Native.errorName(code);
    }
}
