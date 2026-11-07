package com.cipherbird.cb2.bench;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.paseto4j.commons.SecretKey;
import org.paseto4j.version4.Paseto;

/**
 * PASETO v4.local and v4.public through paseto4j, which signs with
 * Bouncy Castle's Ed25519 and expects the application to register that
 * provider. paseto4j handles the cryptography and returns the payload;
 * the claims check (iss, aud, exp) is done here with Jackson, as an
 * application using it would.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class Paseto4jBench {
    SecretKey localKey;
    EdECPrivateKey privateKey;
    EdECPublicKey publicKey;
    String payload;
    String localToken;
    String publicToken;

    /**
     * Makes the keys and one token of each kind.
     *
     * @throws NoSuchAlgorithmException when the JDK has no Ed25519
     */
    @Setup
    public void setup() throws NoSuchAlgorithmException {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        localKey = SecretKey.fromBytes(key);
        KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        privateKey = (EdECPrivateKey) pair.getPrivate();
        publicKey = (EdECPublicKey) pair.getPublic();
        payload = Claims.json();
        localToken = localEncrypt();
        publicToken = publicSign();
    }

    /**
     * Encrypts the claims as a v4.local token.
     *
     * @return the token
     */
    @Benchmark
    public String localEncrypt() {
        return Paseto.encrypt(localKey, payload, "");
    }

    /**
     * Decrypts a v4.local token and checks its claims.
     *
     * @return the subject
     */
    @Benchmark
    public String localDecrypt() {
        return Claims.checkPaseto(Paseto.decrypt(localKey, localToken, ""));
    }

    /**
     * Signs the claims as a v4.public token.
     *
     * @return the token
     */
    @Benchmark
    public String publicSign() {
        return Paseto.sign(privateKey, payload);
    }

    /**
     * Verifies a v4.public token and checks its claims.
     *
     * @return the subject
     * @throws SignatureException when the signature does not verify
     */
    @Benchmark
    public String publicVerify() throws SignatureException {
        return Claims.checkPaseto(Paseto.parse(publicKey, publicToken));
    }
}
