package com.cipherbird.cb2;

/**
 * The cb2 library: loads the JNI glue once and answers what the build
 * offers. The glue is loaded from the path in the system property
 * cb2.jni.library when it is set, otherwise with System.loadLibrary
 * ("cb2_jni") from java.library.path.
 */
public final class Cb2 {
    private static boolean loaded;

    private Cb2() {
    }

    /** Loads the JNI glue; every other class calls this before its first native call. */
    @SuppressWarnings("restricted")
    public static synchronized void load() {
        if (loaded) {
            return;
        }
        String path = System.getProperty("cb2.jni.library");
        if (path != null && !path.isEmpty()) {
            System.load(path);
        } else {
            System.loadLibrary("cb2_jni");
        }
        loaded = true;
    }

    /** The library version string. */
    public static String version() {
        return Native.version();
    }

    /** Whether cb2.public (signing) is available in this build. */
    public static boolean hasPublic() {
        return Native.hasPublic();
    }

    /** Whether kcb2.seal (recipient sealing) is available in this build. */
    public static boolean hasSeal() {
        return Native.hasSeal();
    }

    /** The stable name of an error code, "ok" for 0 and "unknown" for codes the library does not use. */
    public static String errorName(int code) {
        return Native.errorName(code);
    }
}
