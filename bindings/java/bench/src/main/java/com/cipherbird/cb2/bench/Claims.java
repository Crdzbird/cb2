package com.cipherbird.cb2.bench;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * The one claims payload every format carries: iss, sub, aud, exp, iat,
 * jti and the custom claim role. cb2 writes times as RFC 3339 strings,
 * JWT and PASETO as their own conventions (NumericDate for JWT, RFC 3339
 * for PASETO).
 */
final class Claims {
    static final String ISSUER = "https://issuer.example";
    static final String SUBJECT = "user-1";
    static final String AUDIENCE = "api";
    static final String JTI = "0f8b4a52-6c1e-4d2b-9a57-3c2f1e0d9b11";
    static final String ROLE = "admin";
    static final Instant IAT = Instant.now();
    static final Instant EXP = IAT.plusSeconds(3600);

    private static final DateTimeFormatter RFC3339 = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssxxx");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Claims() {
    }

    static String json() {
        return "{\"iss\":\"" + ISSUER + "\",\"sub\":\"" + SUBJECT + "\",\"aud\":\"" + AUDIENCE + "\",\"exp\":\""
                + rfc3339(EXP) + "\",\"iat\":\"" + rfc3339(IAT) + "\",\"jti\":\"" + JTI + "\",\"role\":\"" + ROLE + "\"}";
    }

    /**
     * The validation the JWT libraries and cb2 do on the way back, done by
     * hand for paseto4j, which returns the payload without looking at it:
     * parse the JSON, then check iss, aud and exp.
     */
    static String checkPaseto(String payload) {
        JsonNode node;
        try {
            node = MAPPER.readTree(payload);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        if (!ISSUER.equals(node.path("iss").asText()) || !AUDIENCE.equals(node.path("aud").asText())) {
            throw new IllegalStateException("issuer or audience");
        }
        if (!Instant.parse(node.path("exp").asText()).isAfter(Instant.now())) {
            throw new IllegalStateException("expired");
        }
        return node.path("sub").asText();
    }

    private static String rfc3339(Instant instant) {
        return RFC3339.format(instant.atOffset(ZoneOffset.UTC));
    }
}
