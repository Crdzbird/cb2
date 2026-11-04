package com.cipherbird.cb2;

/**
 * A replay check: called with a token id (or a proof id) while a token is
 * opened or verified, it returns true to accept the id and false to
 * refuse it. An implementation that remembers every id it has accepted
 * turns the second presentation of a token into the replayed verdict.
 * An exception thrown by the check refuses the id.
 */
@FunctionalInterface
public interface ReplayCheck {
    boolean accept(String jti);
}
