package com.cipherbird.cb2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;

class RulesTest {
    @Test
    void emptyRulesAreAnEmptyObject() {
        assertEquals("{}", new Rules().toJson());
        assertNull(new Rules().replayCheck());
        assertNull(new Rules().proofReplayCheck());
    }

    @Test
    void everyMemberIsWritten() {
        ReplayCheck check = jti -> true;
        Rules rules = new Rules().now(1).clockSkew(2).requireExp(false).allowAnyAudience(true).allowAnyIssuer(true)
                .issuer("i\"").audience("a").subject("s").maxTokenBytes(3).maxLifetime(4).replay(check)
                .seenJti("j1", "j2").requireCnf(true).ignoreCnf(false).proof("p").request("GET", "https://h/", "n")
                .proofLifetime(5).proofSeenJti("q").proofReplay(check);
        assertEquals("{\"now\":1,\"clock_skew\":2,\"require_exp\":false,\"allow_any_audience\":true,"
                + "\"allow_any_issuer\":true,\"issuer\":\"i\\\"\",\"audience\":\"a\",\"subject\":\"s\","
                + "\"max_token_bytes\":3,\"max_lifetime\":4,\"replay\":true,\"seen_jti\":[\"j1\",\"j2\"],"
                + "\"require_cnf\":true,\"ignore_cnf\":false,\"proof\":\"p\","
                + "\"request\":{\"htm\":\"GET\",\"htu\":\"https://h/\",\"nonce\":\"n\"},\"proof_lifetime\":5,"
                + "\"proof_seen_jti\":[\"q\"]}", rules.toJson());
        assertSame(check, rules.replayCheck());
        assertSame(check, rules.proofReplayCheck());
    }

    @Test
    void jsonQuoting() {
        assertEquals("\"a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\u00e9\"", Json.quote("a\"b\\c\n\r\t\b\f\u0001\u00e9"));
    }
}
