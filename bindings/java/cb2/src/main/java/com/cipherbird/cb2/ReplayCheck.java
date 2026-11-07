package com.cipherbird.cb2;

/**
 * A replay check: called with a token id (or a proof id) while a token is
 * opened or verified, on the thread that opens it. An implementation that
 * remembers every id it has accepted turns the second presentation of a
 * token into the replayed verdict. An exception thrown by the check
 * refuses the id. Checks shared between threads must be thread-safe, such
 * as {@code ConcurrentHashMap.newKeySet()::add}.
 */
@FunctionalInterface
public interface ReplayCheck {
    /**
     * Decides on one id.
     *
     * @param jti the token id or proof id
     * @return true to accept the id, false to refuse it
     */
    boolean accept(String jti);
}
