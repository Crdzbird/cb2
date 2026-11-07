package com.cipherbird.cb2.bench;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;
import java.util.Set;
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
import org.openjdk.jmh.annotations.Warmup;

/**
 * Nimbus JOSE+JWT: HS256, EdDSA (Ed25519, through Tink) and ES256, each
 * parsed, verified, and its claims checked by DefaultJWTClaimsVerifier
 * for issuer, audience and exp.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
@Fork(2)
public class NimbusBench {
    JWTClaimsSet claims;
    DefaultJWTClaimsVerifier<?> claimsVerifier;
    JWSSigner hmacSigner;
    JWSVerifier hmacVerifier;
    JWSSigner edSigner;
    JWSVerifier edVerifier;
    JWSSigner ecSigner;
    JWSVerifier ecVerifier;
    String hs256;
    String eddsa;
    String es256;

    /**
     * Makes the keys and one token of each kind.
     *
     * @throws JOSEException when a key cannot be made
     */
    @Setup
    public void setup() throws JOSEException {
        claims = new JWTClaimsSet.Builder()
                .issuer(Claims.ISSUER)
                .subject(Claims.SUBJECT)
                .audience(Claims.AUDIENCE)
                .expirationTime(Date.from(Claims.EXP))
                .issueTime(Date.from(Claims.IAT))
                .jwtID(Claims.JTI)
                .claim("role", Claims.ROLE)
                .build();
        claimsVerifier = new DefaultJWTClaimsVerifier<>(Claims.AUDIENCE,
                new JWTClaimsSet.Builder().issuer(Claims.ISSUER).build(), Set.of("exp"));
        byte[] secret = new byte[32];
        new SecureRandom().nextBytes(secret);
        hmacSigner = new MACSigner(secret);
        hmacVerifier = new MACVerifier(secret);
        OctetKeyPair ed = new OctetKeyPairGenerator(Curve.Ed25519).generate();
        edSigner = new Ed25519Signer(ed);
        edVerifier = new Ed25519Verifier(ed.toPublicJWK());
        ECKey ec = new ECKeyGenerator(Curve.P_256).generate();
        ecSigner = new ECDSASigner(ec);
        ecVerifier = new ECDSAVerifier(ec.toPublicJWK());
        hs256 = hs256Sign();
        eddsa = eddsaSign();
        es256 = es256Sign();
    }

    private String sign(JWSAlgorithm alg, JWSSigner signer) throws JOSEException {
        SignedJWT jwt = new SignedJWT(new JWSHeader(alg), claims);
        jwt.sign(signer);
        return jwt.serialize();
    }

    private String verify(String token, JWSVerifier verifier) throws ParseException, JOSEException, BadJWTException {
        SignedJWT jwt = SignedJWT.parse(token);
        if (!jwt.verify(verifier)) {
            throw new IllegalStateException("signature");
        }
        JWTClaimsSet set = jwt.getJWTClaimsSet();
        claimsVerifier.verify(set, null);
        return set.getSubject();
    }

    /**
     * Signs an HS256 JWT.
     *
     * @return the token
     * @throws JOSEException when signing fails
     */
    @Benchmark
    public String hs256Sign() throws JOSEException {
        return sign(JWSAlgorithm.HS256, hmacSigner);
    }

    /**
     * Verifies an HS256 JWT and checks its claims.
     *
     * @return the subject
     * @throws Exception when the token is refused
     */
    @Benchmark
    public String hs256Verify() throws Exception {
        return verify(hs256, hmacVerifier);
    }

    /**
     * Signs an EdDSA (Ed25519) JWT.
     *
     * @return the token
     * @throws JOSEException when signing fails
     */
    @Benchmark
    public String eddsaSign() throws JOSEException {
        return sign(JWSAlgorithm.EdDSA, edSigner);
    }

    /**
     * Verifies an EdDSA JWT and checks its claims.
     *
     * @return the subject
     * @throws Exception when the token is refused
     */
    @Benchmark
    public String eddsaVerify() throws Exception {
        return verify(eddsa, edVerifier);
    }

    /**
     * Signs an ES256 JWT.
     *
     * @return the token
     * @throws JOSEException when signing fails
     */
    @Benchmark
    public String es256Sign() throws JOSEException {
        return sign(JWSAlgorithm.ES256, ecSigner);
    }

    /**
     * Verifies an ES256 JWT and checks its claims.
     *
     * @return the subject
     * @throws Exception when the token is refused
     */
    @Benchmark
    public String es256Verify() throws Exception {
        return verify(es256, ecVerifier);
    }
}
