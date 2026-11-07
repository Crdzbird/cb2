package com.cipherbird.cb2;

import static com.cipherbird.cb2.Support.CLAIMS;
import static com.cipherbird.cb2.Support.rules;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

class KeyLifecycleTest {
    @Test
    void aClosedKeyRefusesUse() {
        LocalKey k = LocalKey.generate();
        k.close();
        assertDoesNotThrow(k::close, "closing twice does nothing");
        assertThrows(IllegalStateException.class, k::paserkId, "a closed key must refuse use");
        assertThrows(IllegalStateException.class, () -> k.setKeyId("x"), "a closed key must refuse a change");
        try (LocalKey other = LocalKey.generate()) {
            assertThrows(IllegalStateException.class, () -> KeyWrap.wrap(other, k), "a closed key cannot be wrapped");
        }
    }

    @Test
    void nullArgumentsAreRefused() {
        try (LocalKey k = LocalKey.generate()) {
            assertThrows(IllegalArgumentException.class, () -> Token.seal(k, null), "null claims");
            assertThrows(IllegalArgumentException.class, () -> Token.open(k, "x", null), "null rules");
            assertThrows(IllegalArgumentException.class, () -> Token.open(null, "x", rules()), "null key");
            assertThrows(IllegalArgumentException.class, () -> LocalKey.fromBytes(null), "null key bytes");
        }
    }

    @Test
    void oneKeyServesManyThreads() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try (LocalKey k = LocalKey.generate()) {
            k.setKeyId("rotation-1");
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < 64; i++) {
                int n = i;
                results.add(pool.submit(() -> {
                    if (n % 16 == 0) {
                        k.setKeyId("rotation-1");
                    }
                    String token = Token.seal(k, CLAIMS);
                    return Token.open(k, token, rules()).contains("\"role\":\"admin\"");
                }));
            }
            for (Future<Boolean> result : results) {
                assertTrue(result.get(), "every thread opens its own token");
            }
        } finally {
            pool.shutdown();
        }
    }

    @Test
    void closeWaitsForCallsInFlight() throws Exception {
        LocalKey k = LocalKey.generate();
        String token = Token.seal(k, CLAIMS);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<String> inFlight = pool.submit(() -> Token.open(k, token, rules().replay(jti -> {
                k.close();
                return true;
            })));
            assertTrue(inFlight.get().contains("\"jti\":\"id-1\""), "the call that was running completes");
            assertThrows(IllegalStateException.class, k::keyId, "the key is closed afterwards");
        } finally {
            pool.shutdown();
        }
    }
}
