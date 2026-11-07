package com.cipherbird.cb2;

/**
 * The error codes of the C ABI, carried by {@link Cb2Exception#code()};
 * 0 is success. {@link Cb2#errorName(int)} gives each its stable name.
 */
public final class Code {
    /** Success (ok). */
    public static final int OK = 0;

    /** The token or text is not authentic or not well formed (invalid). */
    public static final int INVALID = 1;

    /** The token is larger than the limit (too_large). */
    public static final int TOO_LARGE = 2;

    /** An argument was refused, such as weak key bytes or an identifier with hidden characters (argument). */
    public static final int ARGUMENT = 3;

    /** The rules leave out something the library requires, such as an expected issuer (rules_incomplete). */
    public static final int RULES_INCOMPLETE = 4;

    /** The library failed internally (internal). */
    public static final int INTERNAL = 5;

    /** The feature is not in this build (unavailable). */
    public static final int UNAVAILABLE = 6;

    /** The claims are not a valid claims object (claims_malformed). */
    public static final int CLAIMS_MALFORMED = 7;

    /** The claims carry no exp and the rules require one (missing_exp). */
    public static final int MISSING_EXP = 8;

    /** The token is past its exp (expired). */
    public static final int EXPIRED = 9;

    /** The token is before its nbf (not_yet_valid). */
    public static final int NOT_YET_VALID = 10;

    /** The token's iat is in the future (issued_in_future). */
    public static final int ISSUED_IN_FUTURE = 11;

    /** Exp minus iat is longer than the rules allow (lifetime_exceeded). */
    public static final int LIFETIME_EXCEEDED = 12;

    /** Iss is not the expected issuer (issuer_mismatch). */
    public static final int ISSUER_MISMATCH = 13;

    /** Aud is not the expected audience (audience_mismatch). */
    public static final int AUDIENCE_MISMATCH = 14;

    /** Sub is not the expected subject (subject_mismatch). */
    public static final int SUBJECT_MISMATCH = 15;

    /** The token has no jti and a replay check needs one (missing_jti). */
    public static final int MISSING_JTI = 16;

    /** The replay check refused the token id (replayed). */
    public static final int REPLAYED = 17;

    /** The rules require cnf and the token has none (missing_cnf). */
    public static final int MISSING_CNF = 18;

    /** The token is bound by cnf and no holder proof was presented (missing_proof). */
    public static final int MISSING_PROOF = 19;

    /** The holder proof is not authentic under the cnf key (proof_invalid). */
    public static final int PROOF_INVALID = 20;

    /** The holder proof is not well formed (proof_malformed). */
    public static final int PROOF_MALFORMED = 21;

    /** The holder proof is too old (proof_expired). */
    public static final int PROOF_EXPIRED = 22;

    /** The holder proof is for another request or another token (proof_mismatch). */
    public static final int PROOF_MISMATCH = 23;

    /** The proof replay check refused the proof id (proof_replayed). */
    public static final int PROOF_REPLAYED = 24;

    private Code() {
    }
}
