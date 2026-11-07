package com.cipherbird.cb2;

/**
 * The native methods the JNI glue implements. Text crosses as UTF-8
 * byte arrays in both directions and keys as handles.
 */
final class Native {
    static {
        Cb2.load();
    }

    private Native() {
    }

    static native String version();

    static native boolean hasPublic();

    static native boolean hasSeal();

    static native String errorName(int code);

    static native long localKeyGenerate();

    static native long localKeyFromBytes(byte[] bytes);

    static native long localKeyFromPaserk(byte[] text);

    static native byte[] localKeyToPaserk(long key);

    static native byte[] localKeyPaserkId(long key);

    static native byte[] localKeyKeyId(long key);

    static native void localKeySetKeyId(long key, byte[] id);

    static native void localKeyClearKeyId(long key);

    static native void localKeyFree(long key);

    static native long secretKeyGenerate();

    static native long secretKeyFromBytes(byte[] bytes);

    static native long secretKeyFromPaserk(byte[] text);

    static native byte[] secretKeyToPaserk(long key);

    static native long secretKeyPublicKey(long key);

    static native byte[] secretKeyKeyId(long key);

    static native void secretKeySetKeyId(long key, byte[] id);

    static native void secretKeyClearKeyId(long key);

    static native void secretKeyFree(long key);

    static native long publicKeyFromBytes(byte[] bytes);

    static native long publicKeyFromPaserk(byte[] text);

    static native byte[] publicKeyToPaserk(long key);

    static native byte[] publicKeyPaserkId(long key);

    static native byte[] publicKeyKeyId(long key);

    static native void publicKeySetKeyId(long key, byte[] id);

    static native void publicKeyClearKeyId(long key);

    static native void publicKeyFree(long key);

    static native long recipientKeyGenerate();

    static native long recipientKeyFromBytes(byte[] bytes);

    static native long recipientKeyFromPaserk(byte[] text);

    static native byte[] recipientKeyToPaserk(long key);

    static native long recipientKeyPublicKey(long key);

    static native byte[] recipientKeyPaserkId(long key);

    static native void recipientKeyFree(long key);

    static native long recipientPublicKeyFromBytes(byte[] bytes);

    static native long recipientPublicKeyFromPaserk(byte[] text);

    static native byte[] recipientPublicKeyToPaserk(long key);

    static native byte[] recipientPublicKeyPaserkId(long key);

    static native void recipientPublicKeyFree(long key);

    static native byte[] localSeal(long key, byte[] message, byte[] footer, byte[] implicit);

    static native byte[] localOpen(long key, byte[] token, byte[] footer, byte[] implicit, long maxTokenBytes);

    static native byte[] publicSign(long key, byte[] message, byte[] footer, byte[] implicit);

    static native byte[] publicVerify(long key, byte[] token, byte[] footer, byte[] implicit, long maxTokenBytes);

    static native byte[] tokenSeal(long key, byte[] claims, byte[] implicit);

    static native byte[] tokenSign(long key, byte[] claims, byte[] implicit);

    static native byte[] tokenOpen(long key, byte[] token, byte[] rules, byte[] implicit, ReplayCheck replay,
            ReplayCheck proofReplay);

    static native byte[] tokenVerify(long key, byte[] token, byte[] rules, byte[] implicit, ReplayCheck replay,
            ReplayCheck proofReplay);

    static native byte[] peekKeyId(byte[] token);

    static native byte[] compactSeal(long key, long table, byte[] claims, byte[] implicit);

    static native byte[] compactSign(long key, long table, byte[] claims, byte[] implicit);

    static native byte[] compactOpen(long key, long table, byte[] token, byte[] rules, byte[] implicit,
            ReplayCheck replay, ReplayCheck proofReplay);

    static native byte[] compactVerify(long key, long table, byte[] token, byte[] rules, byte[] implicit,
            ReplayCheck replay, ReplayCheck proofReplay);

    static native byte[] compactPeekKeyDigest(byte[] token);

    static native byte[] compactKeyDigest(byte[] id);

    static native long claimTableFromJson(byte[] entries);

    static native byte[] claimTableDigest(long table);

    static native void claimTableFree(long table);

    static native byte[] holderProve(long client, byte[] htm, byte[] htu, byte[] nonce, byte[] accessToken,
            byte[] jti, long now, long lifetime);

    static native byte[] holderProveLocal(long proofKey, byte[] htm, byte[] htu, byte[] nonce, byte[] accessToken,
            byte[] jti, long now, long lifetime);

    static native byte[] holderNormalizeTarget(byte[] uri);

    static native byte[] wrap(long wrapping, long key);

    static native long unwrap(byte[] text, long wrapping);

    static native byte[] seal(long to, long key);

    static native long unseal(byte[] text, long by);
}
