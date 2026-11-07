/**
 * cb2 tokens for Java: cb2.local and cb2.public tokens, claims checked
 * against rules, the experimental compact cb3.local and cb3.public forms,
 * holder proofs, key wrapping and kcb2.seal, over the cb2 C ABI through
 * JNI. The native glue is loaded from this module's own
 * resources when they carry a build for the running platform, otherwise
 * from java.library.path; grant this module native access with
 * {@code --enable-native-access=com.cipherbird.cb2}.
 */
@SuppressWarnings("module")
module com.cipherbird.cb2 {
    exports com.cipherbird.cb2;
}
