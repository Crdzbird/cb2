/*
 * cb2_jni: the JNI glue between com.cipherbird.cb2.Native and the cb2 C
 * ABI. It calls cb2_c.h only, never the C++ headers.
 *
 * Every text argument crosses as a byte[] holding UTF-8 and every text
 * result comes back as a byte[] of UTF-8; the Java side converts. Keys
 * cross as jlong handles. Every result the C ABI allocates is released
 * here with cb2_free, or cb2_free_secret for key material. A non-zero
 * code becomes a thrown com.cipherbird.cb2.Cb2Exception(code, name).
 *
 * Replay checks: the Java side passes objects implementing ReplayCheck;
 * the C callbacks call accept(String) through the JNIEnv of the calling
 * thread, which is sound because the C ABI runs them synchronously inside
 * cb2_token_open, cb2_token_verify, cb2_compact_open and cb2_compact_verify. A Java exception raised by a check
 * is cleared and the id is refused.
 *
 * No C++ exception crosses into the JVM: the only allocations that can
 * throw are the argument copies in read(), which turn std::bad_alloc into
 * a pending OutOfMemoryError, and every entry point returns before calling
 * the C ABI when an exception is pending. Argument copies are wiped when
 * they go out of scope. Handles are never 0 here: the Java side refuses a
 * closed key before it reaches the glue and frees a key only once no call
 * is using it.
 */

#include "cb2_c.h"

#include <jni.h>

#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <vector>

namespace {

jclass g_exception = nullptr;
jclass g_oom = nullptr;
jmethodID g_exception_ctor = nullptr;
jclass g_string = nullptr;
jmethodID g_string_ctor = nullptr;
jstring g_utf8 = nullptr;
jmethodID g_accept = nullptr;

void wipe(std::vector<uint8_t>& v) {
    volatile uint8_t* p = v.data();
    for (size_t i = 0; i < v.size(); i++) p[i] = 0;
}

struct Bytes {
    std::vector<uint8_t> data;
    bool present = false;
    Bytes() = default;
    Bytes(Bytes&&) noexcept = default;
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;
    Bytes& operator=(Bytes&&) = delete;
    ~Bytes() { wipe(data); }
    const uint8_t* ptr() const { return present && !data.empty() ? data.data() : nullptr; }
    const char* chars() const { return reinterpret_cast<const char*>(ptr()); }
    size_t size() const { return data.size(); }
};

void throw_oom(JNIEnv* env, const char* what) noexcept {
    if (env->ExceptionCheck()) return;
    if (g_oom != nullptr) env->ThrowNew(g_oom, what);
}

bool pending(JNIEnv* env) noexcept {
    return env->ExceptionCheck() == JNI_TRUE;
}

Bytes read(JNIEnv* env, jbyteArray array) noexcept {
    Bytes b;
    if (array == nullptr || pending(env)) return b;
    jsize n = env->GetArrayLength(array);
    try {
        b.data.resize(static_cast<size_t>(n));
    } catch (const std::bad_alloc&) {
        throw_oom(env, "cb2: out of memory copying an argument");
        return b;
    }
    b.present = true;
    if (n > 0) env->GetByteArrayRegion(array, 0, n, reinterpret_cast<jbyte*>(b.data.data()));
    return b;
}

jbyteArray to_array(JNIEnv* env, const void* p, size_t n) noexcept {
    if (n > static_cast<size_t>(std::numeric_limits<jsize>::max())) {
        throw_oom(env, "cb2: result too large for a Java array");
        return nullptr;
    }
    jbyteArray a = env->NewByteArray(static_cast<jsize>(n));
    if (a == nullptr) return nullptr;
    if (n > 0) env->SetByteArrayRegion(a, 0, static_cast<jsize>(n), static_cast<const jbyte*>(p));
    return a;
}

void throw_code(JNIEnv* env, int code) noexcept {
    if (env->ExceptionCheck()) return;
    jstring name = env->NewStringUTF(cb2_error_name(code));
    if (name == nullptr) return;
    jobject ex = env->NewObject(g_exception, g_exception_ctor, static_cast<jint>(code), name);
    if (ex != nullptr) env->Throw(static_cast<jthrowable>(ex));
}

jbyteArray take_text(JNIEnv* env, char* s, bool secret) {
    if (s == nullptr) return nullptr;
    jbyteArray a = to_array(env, s, std::strlen(s));
    if (secret) cb2_free_secret(s); else cb2_free(s);
    return a;
}

jbyteArray take_text(JNIEnv* env, char* s, size_t len) {
    if (s == nullptr) return nullptr;
    jbyteArray a = to_array(env, s, len);
    cb2_free(s);
    return a;
}

jbyteArray take_bytes(JNIEnv* env, uint8_t* p, size_t len) {
    if (p == nullptr) return nullptr;
    jbyteArray a = to_array(env, p, len);
    cb2_free(p);
    return a;
}

template <class K>
K* handle(jlong h) {
    return reinterpret_cast<K*>(static_cast<intptr_t>(h));
}

jlong to_handle(const void* p) {
    return static_cast<jlong>(reinterpret_cast<intptr_t>(p));
}

template <class K>
jlong generate(JNIEnv* env, int (*fn)(K**)) {
    K* k = nullptr;
    int rc = fn(&k);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(k);
}

template <class K>
jlong from_bytes(JNIEnv* env, jbyteArray bytes, int (*fn)(const uint8_t*, size_t, K**)) {
    Bytes b = read(env, bytes);
    if (pending(env)) return 0;
    K* k = nullptr;
    int rc = fn(b.ptr(), b.size(), &k);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(k);
}

template <class K>
jlong from_text(JNIEnv* env, jbyteArray text, int (*fn)(const char*, size_t, K**)) {
    Bytes b = read(env, text);
    if (pending(env)) return 0;
    K* k = nullptr;
    int rc = fn(b.chars(), b.size(), &k);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(k);
}

template <class K>
jbyteArray text_of(JNIEnv* env, jlong key, char* (*fn)(const K*), bool secret) {
    return take_text(env, fn(handle<K>(key)), secret);
}

template <class K, class P>
jlong derive(JNIEnv* env, jlong key, int (*fn)(const K*, P**)) {
    P* p = nullptr;
    int rc = fn(handle<K>(key), &p);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(p);
}

template <class K>
void set_id(JNIEnv* env, jlong key, jbyteArray id, int (*fn)(K*, const char*, size_t)) {
    Bytes b = read(env, id);
    if (pending(env)) return;
    int rc = fn(handle<K>(key), b.chars(), b.size());
    if (rc != CB2_OK) throw_code(env, rc);
}

struct Checks {
    JNIEnv* env;
    jobject replay;
    jobject proof;
};

int run_check(JNIEnv* env, jobject check, const char* jti, size_t len) noexcept {
    if (check == nullptr) return 0;
    if (env->PushLocalFrame(8) < 0) {
        env->ExceptionClear();
        return 0;
    }
    int verdict = 0;
    jbyteArray bytes = to_array(env, jti, len);
    if (bytes != nullptr) {
        jobject text = env->NewObject(g_string, g_string_ctor, bytes, g_utf8);
        if (text != nullptr) {
            jboolean ok = env->CallBooleanMethod(check, g_accept, text);
            if (!env->ExceptionCheck() && ok == JNI_TRUE) verdict = 1;
        }
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        verdict = 0;
    }
    env->PopLocalFrame(nullptr);
    return verdict;
}

int replay_trampoline(void* user, const char* jti, size_t len) noexcept {
    Checks* c = static_cast<Checks*>(user);
    return run_check(c->env, c->replay, jti, len);
}

int proof_trampoline(void* user, const char* jti, size_t len) noexcept {
    Checks* c = static_cast<Checks*>(user);
    return run_check(c->env, c->proof, jti, len);
}

template <class K>
jbyteArray produce(JNIEnv* env, jlong key, jbyteArray msg, jbyteArray footer, jbyteArray implicit,
                   int (*fn)(const K*, const uint8_t*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                             char**, size_t*)) {
    Bytes m = read(env, msg);
    Bytes f = read(env, footer);
    Bytes i = read(env, implicit);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    size_t len = 0;
    int rc = fn(handle<K>(key), m.ptr(), m.size(), f.ptr(), f.size(), i.ptr(), i.size(), &out, &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, len);
}

template <class K>
jbyteArray consume(JNIEnv* env, jlong key, jbyteArray token, jbyteArray footer, jbyteArray implicit,
                   jlong max_bytes,
                   int (*fn)(const K*, const char*, size_t, const uint8_t*, size_t, const uint8_t*, size_t,
                             size_t, uint8_t**, size_t*)) {
    Bytes t = read(env, token);
    Bytes f = read(env, footer);
    Bytes i = read(env, implicit);
    if (pending(env)) return nullptr;
    uint8_t* out = nullptr;
    size_t len = 0;
    size_t limit = max_bytes > 0 ? static_cast<size_t>(max_bytes) : 0;
    int rc = fn(handle<K>(key), t.chars(), t.size(), f.ptr(), f.size(), i.ptr(), i.size(), limit, &out, &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_bytes(env, out, len);
}

template <class K>
jbyteArray issue(JNIEnv* env, jlong key, jbyteArray claims, jbyteArray implicit,
                 int (*fn)(const K*, const char*, size_t, const uint8_t*, size_t, char**, size_t*)) {
    Bytes c = read(env, claims);
    Bytes i = read(env, implicit);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    size_t len = 0;
    int rc = fn(handle<K>(key), c.chars(), c.size(), i.ptr(), i.size(), &out, &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, len);
}

template <class K>
jbyteArray check(JNIEnv* env, jlong key, jbyteArray token, jbyteArray rules, jbyteArray implicit,
                 jobject replay, jobject proof,
                 int (*fn)(const K*, const char*, size_t, const char*, size_t, const uint8_t*, size_t,
                           cb2_replay_fn, cb2_replay_fn, void*, char**, size_t*)) {
    Bytes t = read(env, token);
    Bytes r = read(env, rules);
    Bytes i = read(env, implicit);
    if (pending(env)) return nullptr;
    Checks checks{env, replay, proof};
    cb2_replay_fn replay_fn = replay != nullptr ? replay_trampoline : nullptr;
    cb2_replay_fn proof_fn = proof != nullptr ? proof_trampoline : nullptr;
    char* out = nullptr;
    size_t len = 0;
    int rc = fn(handle<K>(key), t.chars(), t.size(), r.chars(), r.size(), i.ptr(), i.size(),
                replay_fn, proof_fn, &checks, &out, &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, len);
}

}

#define CB2_JNI(ret, name) extern "C" JNIEXPORT ret JNICALL Java_com_cipherbird_cb2_Native_##name

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return JNI_ERR;
    jclass exception = env->FindClass("com/cipherbird/cb2/Cb2Exception");
    if (exception == nullptr) return JNI_ERR;
    g_exception = static_cast<jclass>(env->NewGlobalRef(exception));
    g_exception_ctor = env->GetMethodID(g_exception, "<init>", "(ILjava/lang/String;)V");
    if (g_exception_ctor == nullptr) return JNI_ERR;
    jclass oom = env->FindClass("java/lang/OutOfMemoryError");
    if (oom == nullptr) return JNI_ERR;
    g_oom = static_cast<jclass>(env->NewGlobalRef(oom));
    jclass string = env->FindClass("java/lang/String");
    if (string == nullptr) return JNI_ERR;
    g_string = static_cast<jclass>(env->NewGlobalRef(string));
    g_string_ctor = env->GetMethodID(g_string, "<init>", "([BLjava/lang/String;)V");
    if (g_string_ctor == nullptr) return JNI_ERR;
    jstring utf8 = env->NewStringUTF("UTF-8");
    if (utf8 == nullptr) return JNI_ERR;
    g_utf8 = static_cast<jstring>(env->NewGlobalRef(utf8));
    jclass check = env->FindClass("com/cipherbird/cb2/ReplayCheck");
    if (check == nullptr) return JNI_ERR;
    g_accept = env->GetMethodID(check, "accept", "(Ljava/lang/String;)Z");
    if (g_accept == nullptr) return JNI_ERR;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM* vm, void*) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) return;
    if (g_exception != nullptr) env->DeleteGlobalRef(g_exception);
    if (g_oom != nullptr) env->DeleteGlobalRef(g_oom);
    if (g_string != nullptr) env->DeleteGlobalRef(g_string);
    if (g_utf8 != nullptr) env->DeleteGlobalRef(g_utf8);
    g_exception = nullptr;
    g_oom = nullptr;
    g_string = nullptr;
    g_utf8 = nullptr;
}

/* Library */

CB2_JNI(jstring, version)(JNIEnv* env, jclass) {
    return env->NewStringUTF(cb2_version());
}

CB2_JNI(jboolean, hasPublic)(JNIEnv*, jclass) {
    return cb2_has_public() ? JNI_TRUE : JNI_FALSE;
}

CB2_JNI(jboolean, hasSeal)(JNIEnv*, jclass) {
    return cb2_has_seal() ? JNI_TRUE : JNI_FALSE;
}

CB2_JNI(jstring, errorName)(JNIEnv* env, jclass, jint code) {
    return env->NewStringUTF(cb2_error_name(static_cast<int>(code)));
}

/* Local keys */

CB2_JNI(jlong, localKeyGenerate)(JNIEnv* env, jclass) {
    return generate(env, cb2_local_key_generate);
}

CB2_JNI(jlong, localKeyFromBytes)(JNIEnv* env, jclass, jbyteArray bytes) {
    return from_bytes(env, bytes, cb2_local_key_from_bytes);
}

CB2_JNI(jlong, localKeyFromPaserk)(JNIEnv* env, jclass, jbyteArray text) {
    return from_text(env, text, cb2_local_key_from_paserk);
}

CB2_JNI(jbyteArray, localKeyToPaserk)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_local_key_to_paserk, true);
}

CB2_JNI(jbyteArray, localKeyPaserkId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_local_key_paserk_id, false);
}

CB2_JNI(jbyteArray, localKeyKeyId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_local_key_key_id, false);
}

CB2_JNI(void, localKeySetKeyId)(JNIEnv* env, jclass, jlong key, jbyteArray id) {
    set_id(env, key, id, cb2_local_key_set_key_id);
}

CB2_JNI(void, localKeyClearKeyId)(JNIEnv*, jclass, jlong key) {
    cb2_local_key_clear_key_id(handle<cb2_local_key>(key));
}

CB2_JNI(void, localKeyFree)(JNIEnv*, jclass, jlong key) {
    cb2_local_key_free(handle<cb2_local_key>(key));
}

/* Signing pairs */

CB2_JNI(jlong, secretKeyGenerate)(JNIEnv* env, jclass) {
    return generate(env, cb2_secret_key_generate);
}

CB2_JNI(jlong, secretKeyFromBytes)(JNIEnv* env, jclass, jbyteArray bytes) {
    return from_bytes(env, bytes, cb2_secret_key_from_bytes);
}

CB2_JNI(jlong, secretKeyFromPaserk)(JNIEnv* env, jclass, jbyteArray text) {
    return from_text(env, text, cb2_secret_key_from_paserk);
}

CB2_JNI(jbyteArray, secretKeyToPaserk)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_secret_key_to_paserk, true);
}

CB2_JNI(jlong, secretKeyPublicKey)(JNIEnv* env, jclass, jlong key) {
    return derive(env, key, cb2_secret_key_public_key);
}

CB2_JNI(jbyteArray, secretKeyKeyId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_secret_key_key_id, false);
}

CB2_JNI(void, secretKeySetKeyId)(JNIEnv* env, jclass, jlong key, jbyteArray id) {
    set_id(env, key, id, cb2_secret_key_set_key_id);
}

CB2_JNI(void, secretKeyClearKeyId)(JNIEnv*, jclass, jlong key) {
    cb2_secret_key_clear_key_id(handle<cb2_secret_key>(key));
}

CB2_JNI(void, secretKeyFree)(JNIEnv*, jclass, jlong key) {
    cb2_secret_key_free(handle<cb2_secret_key>(key));
}

/* Public halves */

CB2_JNI(jlong, publicKeyFromBytes)(JNIEnv* env, jclass, jbyteArray bytes) {
    return from_bytes(env, bytes, cb2_public_key_from_bytes);
}

CB2_JNI(jlong, publicKeyFromPaserk)(JNIEnv* env, jclass, jbyteArray text) {
    return from_text(env, text, cb2_public_key_from_paserk);
}

CB2_JNI(jbyteArray, publicKeyToPaserk)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_public_key_to_paserk, false);
}

CB2_JNI(jbyteArray, publicKeyPaserkId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_public_key_paserk_id, false);
}

CB2_JNI(jbyteArray, publicKeyKeyId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_public_key_key_id, false);
}

CB2_JNI(void, publicKeySetKeyId)(JNIEnv* env, jclass, jlong key, jbyteArray id) {
    set_id(env, key, id, cb2_public_key_set_key_id);
}

CB2_JNI(void, publicKeyClearKeyId)(JNIEnv*, jclass, jlong key) {
    cb2_public_key_clear_key_id(handle<cb2_public_key>(key));
}

CB2_JNI(void, publicKeyFree)(JNIEnv*, jclass, jlong key) {
    cb2_public_key_free(handle<cb2_public_key>(key));
}

/* Recipient pairs */

CB2_JNI(jlong, recipientKeyGenerate)(JNIEnv* env, jclass) {
    return generate(env, cb2_recipient_key_generate);
}

CB2_JNI(jlong, recipientKeyFromBytes)(JNIEnv* env, jclass, jbyteArray bytes) {
    return from_bytes(env, bytes, cb2_recipient_key_from_bytes);
}

CB2_JNI(jlong, recipientKeyFromPaserk)(JNIEnv* env, jclass, jbyteArray text) {
    return from_text(env, text, cb2_recipient_key_from_paserk);
}

CB2_JNI(jbyteArray, recipientKeyToPaserk)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_recipient_key_to_paserk, true);
}

CB2_JNI(jlong, recipientKeyPublicKey)(JNIEnv* env, jclass, jlong key) {
    return derive(env, key, cb2_recipient_key_public_key);
}

CB2_JNI(jbyteArray, recipientKeyPaserkId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_recipient_key_paserk_id, false);
}

CB2_JNI(void, recipientKeyFree)(JNIEnv*, jclass, jlong key) {
    cb2_recipient_key_free(handle<cb2_recipient_key>(key));
}

CB2_JNI(jlong, recipientPublicKeyFromBytes)(JNIEnv* env, jclass, jbyteArray bytes) {
    return from_bytes(env, bytes, cb2_recipient_public_key_from_bytes);
}

CB2_JNI(jlong, recipientPublicKeyFromPaserk)(JNIEnv* env, jclass, jbyteArray text) {
    return from_text(env, text, cb2_recipient_public_key_from_paserk);
}

CB2_JNI(jbyteArray, recipientPublicKeyToPaserk)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_recipient_public_key_to_paserk, false);
}

CB2_JNI(jbyteArray, recipientPublicKeyPaserkId)(JNIEnv* env, jclass, jlong key) {
    return text_of(env, key, cb2_recipient_public_key_paserk_id, false);
}

CB2_JNI(void, recipientPublicKeyFree)(JNIEnv*, jclass, jlong key) {
    cb2_recipient_public_key_free(handle<cb2_recipient_public_key>(key));
}

/* Raw tokens */

CB2_JNI(jbyteArray, localSeal)(JNIEnv* env, jclass, jlong key, jbyteArray msg, jbyteArray footer,
                               jbyteArray implicit) {
    return produce(env, key, msg, footer, implicit, cb2_local_seal);
}

CB2_JNI(jbyteArray, localOpen)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray footer,
                               jbyteArray implicit, jlong max_bytes) {
    return consume(env, key, token, footer, implicit, max_bytes, cb2_local_open);
}

CB2_JNI(jbyteArray, publicSign)(JNIEnv* env, jclass, jlong key, jbyteArray msg, jbyteArray footer,
                                jbyteArray implicit) {
    return produce(env, key, msg, footer, implicit, cb2_public_sign);
}

CB2_JNI(jbyteArray, publicVerify)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray footer,
                                  jbyteArray implicit, jlong max_bytes) {
    return consume(env, key, token, footer, implicit, max_bytes, cb2_public_verify);
}

/* Claims tokens */

CB2_JNI(jbyteArray, tokenSeal)(JNIEnv* env, jclass, jlong key, jbyteArray claims, jbyteArray implicit) {
    return issue(env, key, claims, implicit, cb2_token_seal);
}

CB2_JNI(jbyteArray, tokenSign)(JNIEnv* env, jclass, jlong key, jbyteArray claims, jbyteArray implicit) {
    return issue(env, key, claims, implicit, cb2_token_sign);
}

CB2_JNI(jbyteArray, tokenOpen)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray rules,
                               jbyteArray implicit, jobject replay, jobject proof) {
    return check(env, key, token, rules, implicit, replay, proof, cb2_token_open);
}

CB2_JNI(jbyteArray, tokenVerify)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray rules,
                                 jbyteArray implicit, jobject replay, jobject proof) {
    return check(env, key, token, rules, implicit, replay, proof, cb2_token_verify);
}

CB2_JNI(jbyteArray, peekKeyId)(JNIEnv* env, jclass, jbyteArray token) {
    Bytes t = read(env, token);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    int rc = cb2_peek_key_id(t.chars(), t.size(), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, false);
}

/* Compact claims tokens */

CB2_JNI(jbyteArray, compactSeal)(JNIEnv* env, jclass, jlong key, jbyteArray claims, jbyteArray implicit) {
    return issue(env, key, claims, implicit, cb2_compact_seal);
}

CB2_JNI(jbyteArray, compactSign)(JNIEnv* env, jclass, jlong key, jbyteArray claims, jbyteArray implicit) {
    return issue(env, key, claims, implicit, cb2_compact_sign);
}

CB2_JNI(jbyteArray, compactOpen)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray rules,
                                 jbyteArray implicit, jobject replay, jobject proof) {
    return check(env, key, token, rules, implicit, replay, proof, cb2_compact_open);
}

CB2_JNI(jbyteArray, compactVerify)(JNIEnv* env, jclass, jlong key, jbyteArray token, jbyteArray rules,
                                   jbyteArray implicit, jobject replay, jobject proof) {
    return check(env, key, token, rules, implicit, replay, proof, cb2_compact_verify);
}

CB2_JNI(jbyteArray, compactPeekKeyDigest)(JNIEnv* env, jclass, jbyteArray token) {
    Bytes t = read(env, token);
    if (pending(env)) return nullptr;
    uint8_t* out = nullptr;
    int rc = cb2_compact_peek_key_digest(t.chars(), t.size(), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_bytes(env, out, CB2_KEY_DIGEST_BYTES);
}

CB2_JNI(jbyteArray, compactKeyDigest)(JNIEnv* env, jclass, jbyteArray id) {
    Bytes i = read(env, id);
    if (pending(env)) return nullptr;
    uint8_t* out = nullptr;
    int rc = cb2_compact_key_digest(i.chars(), i.size(), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_bytes(env, out, CB2_KEY_DIGEST_BYTES);
}

/* Holder proofs */

CB2_JNI(jbyteArray, holderProve)(JNIEnv* env, jclass, jlong client, jbyteArray htm, jbyteArray htu,
                                 jbyteArray nonce, jbyteArray access, jbyteArray jti, jlong now,
                                 jlong lifetime) {
    Bytes m = read(env, htm);
    Bytes u = read(env, htu);
    Bytes n = read(env, nonce);
    Bytes a = read(env, access);
    Bytes j = read(env, jti);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    size_t len = 0;
    int rc = cb2_holder_prove(handle<cb2_secret_key>(client), m.chars(), m.size(), u.chars(), u.size(),
                              n.present ? n.chars() : nullptr, n.size(), a.chars(), a.size(), j.chars(),
                              j.size(), static_cast<int64_t>(now), static_cast<int64_t>(lifetime), &out,
                              &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, len);
}

CB2_JNI(jbyteArray, holderProveLocal)(JNIEnv* env, jclass, jlong proof_key, jbyteArray htm, jbyteArray htu,
                                      jbyteArray nonce, jbyteArray access, jbyteArray jti, jlong now,
                                      jlong lifetime) {
    Bytes m = read(env, htm);
    Bytes u = read(env, htu);
    Bytes n = read(env, nonce);
    Bytes a = read(env, access);
    Bytes j = read(env, jti);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    size_t len = 0;
    int rc = cb2_holder_prove_local(handle<cb2_local_key>(proof_key), m.chars(), m.size(), u.chars(), u.size(),
                                    n.present ? n.chars() : nullptr, n.size(), a.chars(), a.size(), j.chars(),
                                    j.size(), static_cast<int64_t>(now), static_cast<int64_t>(lifetime), &out,
                                    &len);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, len);
}

CB2_JNI(jbyteArray, holderNormalizeTarget)(JNIEnv* env, jclass, jbyteArray uri) {
    Bytes u = read(env, uri);
    if (pending(env)) return nullptr;
    char* out = nullptr;
    int rc = cb2_holder_normalize_target(u.chars(), u.size(), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, false);
}

/* Key wrapping and sealing */

CB2_JNI(jbyteArray, wrap)(JNIEnv* env, jclass, jlong wrapping, jlong key) {
    char* out = nullptr;
    int rc = cb2_wrap(handle<cb2_local_key>(wrapping), handle<cb2_local_key>(key), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, false);
}

CB2_JNI(jlong, unwrap)(JNIEnv* env, jclass, jbyteArray text, jlong wrapping) {
    Bytes t = read(env, text);
    if (pending(env)) return 0;
    cb2_local_key* out = nullptr;
    int rc = cb2_unwrap(t.chars(), t.size(), handle<cb2_local_key>(wrapping), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(out);
}

CB2_JNI(jbyteArray, seal)(JNIEnv* env, jclass, jlong to, jlong key) {
    char* out = nullptr;
    int rc = cb2_seal(handle<cb2_recipient_public_key>(to), handle<cb2_local_key>(key), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return nullptr;
    }
    return take_text(env, out, false);
}

CB2_JNI(jlong, unseal)(JNIEnv* env, jclass, jbyteArray text, jlong by) {
    Bytes t = read(env, text);
    if (pending(env)) return 0;
    cb2_local_key* out = nullptr;
    int rc = cb2_unseal(t.chars(), t.size(), handle<cb2_recipient_key>(by), &out);
    if (rc != CB2_OK) {
        throw_code(env, rc);
        return 0;
    }
    return to_handle(out);
}
