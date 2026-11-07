package com.cipherbird.cb2.bench;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.SecureDigestAlgorithm;
import java.security.Key;
import java.security.KeyPair;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
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

/** JJWT: HS256, EdDSA (Ed25519) and ES256, parsed with issuer and audience required and exp checked. */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class JjwtBench {
    SecretKey hmacKey;
    KeyPair edKeys;
    KeyPair ecKeys;
    String hs256;
    String eddsa;
    String es256;

    /** Makes the keys and one token of each kind. */
    @Setup
    public void setup() {
        hmacKey = Jwts.SIG.HS256.key().build();
        edKeys = Jwks.CRV.Ed25519.keyPair().build();
        ecKeys = Jwts.SIG.ES256.keyPair().build();
        hs256 = hs256Sign();
        eddsa = eddsaSign();
        es256 = es256Sign();
    }

    private static <K extends Key> String sign(K key, SecureDigestAlgorithm<? super K, ?> alg) {
        return Jwts.builder()
                .issuer(Claims.ISSUER)
                .subject(Claims.SUBJECT)
                .audience().add(Claims.AUDIENCE).and()
                .expiration(Date.from(Claims.EXP))
                .issuedAt(Date.from(Claims.IAT))
                .id(Claims.JTI)
                .claim("role", Claims.ROLE)
                .signWith(key, alg)
                .compact();
    }

    /**
     * Signs an HS256 JWT.
     *
     * @return the token
     */
    @Benchmark
    public String hs256Sign() {
        return sign(hmacKey, Jwts.SIG.HS256);
    }

    /**
     * Verifies an HS256 JWT and checks its claims.
     *
     * @return the subject
     */
    @Benchmark
    public String hs256Verify() {
        return Jwts.parser().verifyWith(hmacKey).requireIssuer(Claims.ISSUER).requireAudience(Claims.AUDIENCE).build()
                .parseSignedClaims(hs256).getPayload().getSubject();
    }

    /**
     * Signs an EdDSA (Ed25519) JWT.
     *
     * @return the token
     */
    @Benchmark
    public String eddsaSign() {
        return sign(edKeys.getPrivate(), Jwts.SIG.EdDSA);
    }

    /**
     * Verifies an EdDSA JWT and checks its claims.
     *
     * @return the subject
     */
    @Benchmark
    public String eddsaVerify() {
        return Jwts.parser().verifyWith(edKeys.getPublic()).requireIssuer(Claims.ISSUER)
                .requireAudience(Claims.AUDIENCE).build().parseSignedClaims(eddsa).getPayload().getSubject();
    }

    /**
     * Signs an ES256 JWT.
     *
     * @return the token
     */
    @Benchmark
    public String es256Sign() {
        return sign(ecKeys.getPrivate(), Jwts.SIG.ES256);
    }

    /**
     * Verifies an ES256 JWT and checks its claims.
     *
     * @return the subject
     */
    @Benchmark
    public String es256Verify() {
        return Jwts.parser().verifyWith(ecKeys.getPublic()).requireIssuer(Claims.ISSUER)
                .requireAudience(Claims.AUDIENCE).build().parseSignedClaims(es256).getPayload().getSubject();
    }
}
