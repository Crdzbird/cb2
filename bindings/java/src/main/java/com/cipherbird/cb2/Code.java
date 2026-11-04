package com.cipherbird.cb2;

/** The error codes of the C ABI; 0 is success. */
public final class Code {
    public static final int OK = 0;
    public static final int INVALID = 1;
    public static final int TOO_LARGE = 2;
    public static final int ARGUMENT = 3;
    public static final int RULES_INCOMPLETE = 4;
    public static final int INTERNAL = 5;
    public static final int UNAVAILABLE = 6;
    public static final int CLAIMS_MALFORMED = 7;
    public static final int MISSING_EXP = 8;
    public static final int EXPIRED = 9;
    public static final int NOT_YET_VALID = 10;
    public static final int ISSUED_IN_FUTURE = 11;
    public static final int LIFETIME_EXCEEDED = 12;
    public static final int ISSUER_MISMATCH = 13;
    public static final int AUDIENCE_MISMATCH = 14;
    public static final int SUBJECT_MISMATCH = 15;
    public static final int MISSING_JTI = 16;
    public static final int REPLAYED = 17;
    public static final int MISSING_CNF = 18;
    public static final int MISSING_PROOF = 19;
    public static final int PROOF_INVALID = 20;
    public static final int PROOF_MALFORMED = 21;
    public static final int PROOF_EXPIRED = 22;
    public static final int PROOF_MISMATCH = 23;
    public static final int PROOF_REPLAYED = 24;

    private Code() {
    }
}
