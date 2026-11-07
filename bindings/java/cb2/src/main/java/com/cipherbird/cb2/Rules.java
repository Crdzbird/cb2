package com.cipherbird.cb2;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * The rules a token is opened or verified against, serialised to the
 * rules JSON of the C ABI by {@link #toJson()}. Every member is optional;
 * the library applies its defaults for the absent ones (require_exp on,
 * clock_skew 0, max_token_bytes 16384, proof_lifetime 60) and refuses an
 * incomplete set with rules_incomplete. The replay checks are passed to
 * the glue beside the JSON. A Rules is a mutable builder: build one per
 * check, or share one only once it is no longer changed.
 */
public final class Rules {
    private Long now;
    private Long clockSkew;
    private Boolean requireExp;
    private Boolean allowAnyAudience;
    private Boolean allowAnyIssuer;
    private String issuer;
    private String audience;
    private String subject;
    private Long maxTokenBytes;
    private Long maxLifetime;
    private ReplayCheck replay;
    private List<String> seenJti;
    private Boolean requireCnf;
    private Boolean ignoreCnf;
    private String proof;
    private String htm;
    private String htu;
    private String nonce;
    private Long proofLifetime;
    private List<String> proofSeenJti;
    private ReplayCheck proofReplay;

    /** Empty rules; set at least the expected issuer and audience. */
    public Rules() {
    }

    /**
     * Sets the clock the token is checked at.
     *
     * @param unixSeconds the time in Unix seconds; the system clock when unset
     * @return these rules
     */
    public Rules now(long unixSeconds) {
        this.now = unixSeconds;
        return this;
    }

    /**
     * Sets the clock skew tolerated on exp, nbf and iat.
     *
     * @param seconds the skew in seconds, 0 by default
     * @return these rules
     */
    public Rules clockSkew(long seconds) {
        this.clockSkew = seconds;
        return this;
    }

    /**
     * Sets whether a token must carry exp.
     *
     * @param value true by default
     * @return these rules
     */
    public Rules requireExp(boolean value) {
        this.requireExp = value;
        return this;
    }

    /**
     * Accepts any audience instead of requiring an expected one.
     *
     * @param value true to accept any audience
     * @return these rules
     */
    public Rules allowAnyAudience(boolean value) {
        this.allowAnyAudience = value;
        return this;
    }

    /**
     * Accepts any issuer instead of requiring an expected one.
     *
     * @param value true to accept any issuer
     * @return these rules
     */
    public Rules allowAnyIssuer(boolean value) {
        this.allowAnyIssuer = value;
        return this;
    }

    /**
     * Sets the expected issuer.
     *
     * @param value the issuer iss must equal
     * @return these rules
     */
    public Rules issuer(String value) {
        this.issuer = value;
        return this;
    }

    /**
     * Sets the expected audience.
     *
     * @param value the audience aud must hold
     * @return these rules
     */
    public Rules audience(String value) {
        this.audience = value;
        return this;
    }

    /**
     * Sets the expected subject.
     *
     * @param value the subject sub must equal
     * @return these rules
     */
    public Rules subject(String value) {
        this.subject = value;
        return this;
    }

    /**
     * Sets the largest token accepted.
     *
     * @param bytes the limit in bytes, 16384 by default
     * @return these rules
     */
    public Rules maxTokenBytes(long bytes) {
        this.maxTokenBytes = bytes;
        return this;
    }

    /**
     * Sets the longest lifetime (exp minus iat) accepted.
     *
     * @param seconds the limit in seconds; unset by default
     * @return these rules
     */
    public Rules maxLifetime(long seconds) {
        this.maxLifetime = seconds;
        return this;
    }

    /**
     * Runs check on the token id; an id it refuses is the replayed verdict, and a token without jti is missing_jti.
     *
     * @param check the replay check
     * @return these rules
     */
    public Rules replay(ReplayCheck check) {
        this.replay = check;
        return this;
    }

    /**
     * Token ids the built-in replay check refuses, for tests and simple stores.
     *
     * @param ids the ids already seen
     * @return these rules
     */
    public Rules seenJti(Collection<String> ids) {
        this.seenJti = ids == null ? null : new ArrayList<>(ids);
        return this;
    }

    /**
     * Token ids the built-in replay check refuses, for tests and simple stores.
     *
     * @param ids the ids already seen
     * @return these rules
     */
    public Rules seenJti(String... ids) {
        return seenJti(Arrays.asList(ids));
    }

    /**
     * Requires a cnf claim, refusing unbound tokens with missing_cnf.
     *
     * @param value true to require cnf
     * @return these rules
     */
    public Rules requireCnf(boolean value) {
        this.requireCnf = value;
        return this;
    }

    /**
     * Ignores a cnf claim instead of demanding a holder proof.
     *
     * @param value true to ignore cnf
     * @return these rules
     */
    public Rules ignoreCnf(boolean value) {
        this.ignoreCnf = value;
        return this;
    }

    /**
     * Sets the holder proof presented with the request.
     *
     * @param value the proof text
     * @return these rules
     */
    public Rules proof(String value) {
        this.proof = value;
        return this;
    }

    /**
     * Sets the request the proof must match, with no server nonce.
     *
     * @param htm the request method
     * @param htu the request target as the server sees it, an absolute URI
     * @return these rules
     */
    public Rules request(String htm, String htu) {
        return request(htm, htu, null);
    }

    /**
     * Sets the request the proof must match, with a server nonce.
     *
     * @param htm the request method
     * @param htu the request target as the server sees it, an absolute URI
     * @param nonce the nonce the server issued, or null for none
     * @return these rules
     */
    public Rules request(String htm, String htu, String nonce) {
        this.htm = htm;
        this.htu = htu;
        this.nonce = nonce;
        return this;
    }

    /**
     * Sets how long a proof stays fresh.
     *
     * @param seconds the lifetime in seconds, 60 by default
     * @return these rules
     */
    public Rules proofLifetime(long seconds) {
        this.proofLifetime = seconds;
        return this;
    }

    /**
     * Proof ids the built-in proof replay check refuses; when set, the proof callback does not run.
     *
     * @param ids the proof ids already seen
     * @return these rules
     */
    public Rules proofSeenJti(Collection<String> ids) {
        this.proofSeenJti = ids == null ? null : new ArrayList<>(ids);
        return this;
    }

    /**
     * Proof ids the built-in proof replay check refuses; when set, the proof callback does not run.
     *
     * @param ids the proof ids already seen
     * @return these rules
     */
    public Rules proofSeenJti(String... ids) {
        return proofSeenJti(Arrays.asList(ids));
    }

    /**
     * Runs check on the proof id; an id it refuses is the proof_replayed verdict.
     *
     * @param check the proof replay check
     * @return these rules
     */
    public Rules proofReplay(ReplayCheck check) {
        this.proofReplay = check;
        return this;
    }

    /**
     * The replay check passed to the glue beside the JSON.
     *
     * @return the check, or null when none is set
     */
    public ReplayCheck replayCheck() {
        return replay;
    }

    /**
     * The proof replay check passed to the glue beside the JSON.
     *
     * @return the check, or null when none is set
     */
    public ReplayCheck proofReplayCheck() {
        return proofReplay;
    }

    /**
     * The rules JSON the C ABI takes.
     *
     * @return the rules as a JSON object
     */
    public String toJson() {
        JsonObject o = new JsonObject();
        o.number("now", now);
        o.number("clock_skew", clockSkew);
        o.bool("require_exp", requireExp);
        o.bool("allow_any_audience", allowAnyAudience);
        o.bool("allow_any_issuer", allowAnyIssuer);
        o.string("issuer", issuer);
        o.string("audience", audience);
        o.string("subject", subject);
        o.number("max_token_bytes", maxTokenBytes);
        o.number("max_lifetime", maxLifetime);
        o.bool("replay", replay == null ? null : Boolean.TRUE);
        o.strings("seen_jti", seenJti);
        o.bool("require_cnf", requireCnf);
        o.bool("ignore_cnf", ignoreCnf);
        o.string("proof", proof);
        if (htm != null || htu != null || nonce != null) {
            JsonObject request = new JsonObject();
            request.string("htm", htm);
            request.string("htu", htu);
            request.string("nonce", nonce);
            o.raw("request", request.toString());
        }
        o.number("proof_lifetime", proofLifetime);
        o.strings("proof_seen_jti", proofSeenJti);
        return o.toString();
    }
}
