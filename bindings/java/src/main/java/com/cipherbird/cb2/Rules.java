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
 * the glue beside the JSON.
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

    /** The clock as Unix seconds; the system clock when unset. */
    public Rules now(long unixSeconds) {
        this.now = unixSeconds;
        return this;
    }

    /** Tolerated clock skew in seconds. */
    public Rules clockSkew(long seconds) {
        this.clockSkew = seconds;
        return this;
    }

    /** Whether a token must carry exp. */
    public Rules requireExp(boolean value) {
        this.requireExp = value;
        return this;
    }

    /** Accepts any audience instead of requiring an expected one. */
    public Rules allowAnyAudience(boolean value) {
        this.allowAnyAudience = value;
        return this;
    }

    /** Accepts any issuer instead of requiring an expected one. */
    public Rules allowAnyIssuer(boolean value) {
        this.allowAnyIssuer = value;
        return this;
    }

    /** The expected issuer. */
    public Rules issuer(String value) {
        this.issuer = value;
        return this;
    }

    /** The expected audience. */
    public Rules audience(String value) {
        this.audience = value;
        return this;
    }

    /** The expected subject. */
    public Rules subject(String value) {
        this.subject = value;
        return this;
    }

    /** The largest token accepted, in bytes. */
    public Rules maxTokenBytes(long bytes) {
        this.maxTokenBytes = bytes;
        return this;
    }

    /** The longest lifetime (exp minus iat) accepted, in seconds. */
    public Rules maxLifetime(long seconds) {
        this.maxLifetime = seconds;
        return this;
    }

    /** Runs check on the token id; a refused id is the replayed verdict. */
    public Rules replay(ReplayCheck check) {
        this.replay = check;
        return this;
    }

    /** Token ids the built-in replay check refuses, for tests and simple stores. */
    public Rules seenJti(Collection<String> ids) {
        this.seenJti = ids == null ? null : new ArrayList<>(ids);
        return this;
    }

    /** Token ids the built-in replay check refuses, for tests and simple stores. */
    public Rules seenJti(String... ids) {
        return seenJti(Arrays.asList(ids));
    }

    /** Requires a cnf claim, refusing unbound tokens with missing_cnf. */
    public Rules requireCnf(boolean value) {
        this.requireCnf = value;
        return this;
    }

    /** Ignores a cnf claim instead of demanding a proof. */
    public Rules ignoreCnf(boolean value) {
        this.ignoreCnf = value;
        return this;
    }

    /** The holder proof presented with the request. */
    public Rules proof(String value) {
        this.proof = value;
        return this;
    }

    /** The request the proof must match: method, target and no nonce. */
    public Rules request(String htm, String htu) {
        return request(htm, htu, null);
    }

    /** The request the proof must match: method, target and server nonce. */
    public Rules request(String htm, String htu, String nonce) {
        this.htm = htm;
        this.htu = htu;
        this.nonce = nonce;
        return this;
    }

    /** How long a proof stays fresh, in seconds. */
    public Rules proofLifetime(long seconds) {
        this.proofLifetime = seconds;
        return this;
    }

    /** Proof ids the built-in proof replay check refuses; otherwise the proof callback runs. */
    public Rules proofSeenJti(Collection<String> ids) {
        this.proofSeenJti = ids == null ? null : new ArrayList<>(ids);
        return this;
    }

    /** Proof ids the built-in proof replay check refuses; otherwise the proof callback runs. */
    public Rules proofSeenJti(String... ids) {
        return proofSeenJti(Arrays.asList(ids));
    }

    /** Runs check on the proof id; a refused id is the proof_replayed verdict. */
    public Rules proofReplay(ReplayCheck check) {
        this.proofReplay = check;
        return this;
    }

    /** The replay check, or null when none is set. */
    public ReplayCheck replayCheck() {
        return replay;
    }

    /** The proof replay check, or null when none is set. */
    public ReplayCheck proofReplayCheck() {
        return proofReplay;
    }

    /** The rules JSON the C ABI takes. */
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
