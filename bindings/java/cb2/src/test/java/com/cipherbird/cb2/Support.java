package com.cipherbird.cb2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.function.Executable;

final class Support {
    static final String CLAIMS = "{\"iss\":\"https://issuer.example\",\"sub\":\"user-1\",\"aud\":\"api\","
            + "\"exp\":\"2099-01-01T00:00:00+00:00\",\"jti\":\"id-1\",\"role\":\"admin\"}";
    static final long NOW = 1700000000L;
    static final String TARGET = "https://api.example/v1/me";

    private Support() {
    }

    static Rules rules() {
        return new Rules().issuer("https://issuer.example").audience("api").now(NOW);
    }

    static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String bound(String cnf) {
        return "{\"iss\":\"https://issuer.example\",\"aud\":\"api\",\"exp\":\"2099-01-01T00:00:00+00:00\","
                + "\"cnf\":" + Json.quote(cnf) + "}";
    }

    static void expect(int code, String what, Executable action) {
        Cb2Exception e = assertThrows(Cb2Exception.class, action, what);
        assertEquals(Cb2.errorName(code), e.name(), what);
        assertEquals(code, e.code(), what);
    }
}
