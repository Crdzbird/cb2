package com.cipherbird.cb2.bench;

import com.cipherbird.cb2.Compact;
import com.cipherbird.cb2.LocalKey;
import com.cipherbird.cb2.PublicKey;
import com.cipherbird.cb2.Rules;
import com.cipherbird.cb2.SecretKey;
import com.cipherbird.cb2.Token;
import java.util.concurrent.TimeUnit;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;

/**
 * cb2.local and cb2.public, and their compact cb3.local and cb3.public
 * forms, through the Java bridge, claims checked against issuer, audience
 * and exp.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(value = 2, jvmArgsAppend = "--enable-native-access=ALL-UNNAMED")
public class Cb2Bench {
    private LocalKey localKey;
    private SecretKey secretKey;
    private PublicKey publicKey;
    private String claims;
    private String localToken;
    private String publicToken;
    private String compactLocalToken;
    private String compactPublicToken;

    /** Makes the keys and one token of each kind. */
    @Setup
    public void setup() {
        localKey = LocalKey.generate();
        secretKey = SecretKey.generate();
        publicKey = secretKey.publicKey();
        claims = Claims.json();
        localToken = Token.seal(localKey, claims);
        publicToken = Token.sign(secretKey, claims);
        compactLocalToken = Compact.seal(localKey, claims);
        compactPublicToken = Compact.sign(secretKey, claims);
    }

    /** Releases the keys. */
    @TearDown
    public void tearDown() {
        localKey.close();
        publicKey.close();
        secretKey.close();
    }

    private static Rules rules() {
        return new Rules().issuer(Claims.ISSUER).audience(Claims.AUDIENCE);
    }

    /**
     * Seals the claims as a cb2.local token.
     *
     * @return the token
     */
    @Benchmark
    public String localSeal() {
        return Token.seal(localKey, claims);
    }

    /**
     * Opens a cb2.local token and checks its claims.
     *
     * @return the claims JSON
     */
    @Benchmark
    public String localOpen() {
        return Token.open(localKey, localToken, rules());
    }

    /**
     * Signs the claims as a cb2.public token (Ed25519 and ML-DSA-65).
     *
     * @return the token
     */
    @Benchmark
    public String publicSign() {
        return Token.sign(secretKey, claims);
    }

    /**
     * Verifies a cb2.public token (both signatures) and checks its claims.
     *
     * @return the claims JSON
     */
    @Benchmark
    public String publicVerify() {
        return Token.verify(publicKey, publicToken, rules());
    }

    /**
     * Seals the claims as a compact cb3.local token.
     *
     * @return the token
     */
    @Benchmark
    public String compactLocalSeal() {
        return Compact.seal(localKey, claims);
    }

    /**
     * Opens a compact cb3.local token and checks its claims.
     *
     * @return the claims JSON
     */
    @Benchmark
    public String compactLocalOpen() {
        return Compact.open(localKey, compactLocalToken, rules());
    }

    /**
     * Signs the claims as a compact cb3.public token.
     *
     * @return the token
     */
    @Benchmark
    public String compactPublicSign() {
        return Compact.sign(secretKey, claims);
    }

    /**
     * Verifies a compact cb3.public token and checks its claims.
     *
     * @return the claims JSON
     */
    @Benchmark
    public String compactPublicVerify() {
        return Compact.verify(publicKey, compactPublicToken, rules());
    }
}
