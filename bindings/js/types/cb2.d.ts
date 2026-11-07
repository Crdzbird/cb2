/**
 * Type declarations for cb2: the C ABI of cb2 compiled to WebAssembly, one
 * build for Node and browsers. types/cb2.d.cts is an exact copy for
 * CommonJS consumers; edit this file and run `npm run types:sync`.
 *
 * @packageDocumentation
 */

declare const kind: unique symbol;

/** Bytes, or a string taken as its UTF-8 encoding. */
export type Bytes = Uint8Array | string;

/** An optional byte argument: null and undefined mean empty. */
export type OptionalBytes = Bytes | null | undefined;

/** A JSON value, as a custom claim may carry. */
export type JsonValue =
    | string
    | number
    | boolean
    | null
    | readonly JsonValue[]
    | { readonly [member: string]: JsonValue };

/**
 * The stable verdict names of the library, exactly those of
 * docs/PROTOCOL.md, in the order of their codes 1 to 24.
 */
export type Cb2ErrorName =
    | "invalid"
    | "too_large"
    | "argument"
    | "rules_incomplete"
    | "internal"
    | "unavailable"
    | "claims_malformed"
    | "missing_exp"
    | "expired"
    | "not_yet_valid"
    | "issued_in_future"
    | "lifetime_exceeded"
    | "issuer_mismatch"
    | "audience_mismatch"
    | "subject_mismatch"
    | "missing_jti"
    | "replayed"
    | "missing_cnf"
    | "missing_proof"
    | "proof_invalid"
    | "proof_malformed"
    | "proof_expired"
    | "proof_mismatch"
    | "proof_replayed";

/**
 * A refusal from the library. Every refused token, key or argument throws
 * one; nothing else is thrown for a refusal.
 */
export declare class Cb2Error extends Error {
    /**
     * @param code the cb2_code value, 1 and up
     * @param name the verdict name cb2_error_name gives for it
     */
    constructor(code: number, name: Cb2ErrorName);
    /** The cb2_code value of the C ABI, 1 to 24. */
    code: number;
    /** The stable verdict name, such as "invalid", "expired" or "replayed". */
    name: Cb2ErrorName;
}

/**
 * Options for {@link load}, passed to the Emscripten factory. Give
 * locateFile when cb2_core.wasm is not served next to cb2_core.js, or
 * wasmBinary with its bytes already fetched; any other Emscripten module
 * option is passed through as well.
 */
export interface LoadOptions {
    /**
     * Returns the URL or path of a file the core needs. It is called with
     * "cb2_core.wasm" and the directory of cb2_core.js.
     */
    locateFile?: (path: string, prefix: string) => string;
    /** The bytes of cb2_core.wasm, to skip fetching it. */
    wasmBinary?: ArrayBuffer | Uint8Array;
    /**
     * Any other Emscripten module option, such as instantiateWasm(imports,
     * done) to instantiate the wasm yourself; it takes precedence over
     * wasmBinary.
     */
    [option: string]: unknown;
}

/** What every key handle has. */
interface KeyHandle {
    /** The raw handle into the wasm heap; throws once the key is freed. */
    readonly ptr: number;
    /** True once {@link KeyHandle.free} ran. */
    readonly freed: boolean;
    /** The PASERK text of the key; for a secret key it is secret too. */
    toPaserk(): string;
    /** Releases the handle and wipes the key; safe to call twice. */
    free(): void;
}

/** What the three signing and local key types have: an id for the footer. */
interface KeyIdHandle {
    /** The key id bound into token footers; null when cleared. */
    readonly keyId: string | null;
    /** Sets the key id; throws argument for an id the library refuses. */
    setKeyId(id: string): this;
    /** Clears the key id, so tokens carry none. */
    clearKeyId(): this;
}

/** A 32-byte cb2.local key (kcb2.local). */
export interface LocalKey extends KeyHandle, KeyIdHandle {
    readonly [kind]: "LocalKey";
    /** The PASERK id, kcb2.lid. followed by the id. */
    paserkId(): string;
}

/** A cb2.public signing pair, Ed25519 and ML-DSA-65 (kcb2.secret). */
export interface SecretKey extends KeyHandle, KeyIdHandle {
    readonly [kind]: "SecretKey";
    /** The public half, as a new handle. */
    publicKey(): PublicKey;
}

/** The public half of a signing pair (kcb2.public). */
export interface PublicKey extends KeyHandle, KeyIdHandle {
    readonly [kind]: "PublicKey";
    /** The PASERK id, kcb2.pid. followed by the id. */
    paserkId(): string;
}

/** An X-Wing recipient pair for kcb2.seal (kcb2.recipient-secret). */
export interface RecipientKey extends KeyHandle {
    readonly [kind]: "RecipientKey";
    /** The public half, as a new handle. */
    publicKey(): RecipientPublicKey;
    /** The PASERK id of the pair, kcb2.rid. followed by the id. */
    paserkId(): string;
}

/** The public half of a recipient pair (kcb2.recipient). */
export interface RecipientPublicKey extends KeyHandle {
    readonly [kind]: "RecipientPublicKey";
    /** The PASERK id, kcb2.rid. followed by the id. */
    paserkId(): string;
}

/** The constructors every key class has. */
interface KeyConstructor<K> {
    /** Wraps a raw handle from the core; the static constructors are the usual way in. */
    new (ptr: number): K;
    readonly prototype: K;
    /** A key from its raw bytes; throws argument when they are not acceptable. */
    fromBytes(bytes: Uint8Array): K;
    /** A key from its PASERK text; throws argument when it is not one. */
    fromPaserk(text: string): K;
}

/** The constructors of a key type that can be generated. */
interface GeneratedKeyConstructor<K> extends KeyConstructor<K> {
    /** A fresh random key. */
    generate(): K;
}

/** The registered claims as strings, times in RFC 3339, plus custom claims. */
export interface Claims {
    /** Issuer. */
    iss?: string;
    /** Subject. */
    sub?: string;
    /** Audience: one string. */
    aud?: string;
    /** Expiry, RFC 3339, such as 2099-01-01T00:00:00+00:00. */
    exp?: string;
    /** Not before, RFC 3339. */
    nbf?: string;
    /** Issued at, RFC 3339. */
    iat?: string;
    /** Token id, for replay checks. */
    jti?: string;
    /** Confirmation key for holder proofs: a kcb2.public or kcb2.local PASERK. */
    cnf?: string;
    /** Custom claims, any JSON value. */
    [claim: string]: JsonValue | undefined;
}

/** One request a holder proof is bound to. */
export interface HolderRequest {
    /** The HTTP method, such as GET. */
    htm: string;
    /** The request target; normalized as {@link Cb2.Holder}.normalizeTarget does. */
    htu: string;
    /** A server nonce, when the server issued one. */
    nonce?: string;
}

/**
 * A replay check: returns true to accept the id the first time it is seen
 * and false to refuse it. An exception thrown inside refuses the id.
 */
export type ReplayCheck = (jti: string) => boolean;

/**
 * The rules a claims token is opened or verified under, mirroring the
 * rules JSON of bindings/c/include/cb2_c.h member for member. Either
 * issuer or allow_any_issuer, and either audience or allow_any_audience,
 * is required; without them the call throws rules_incomplete.
 */
export interface Rules {
    /** Unix seconds; the clock when absent. */
    now?: number;
    /** Seconds of clock skew allowed, default 0. */
    clock_skew?: number;
    /** Whether exp is required, default true. */
    require_exp?: boolean;
    /** Accept any audience; otherwise audience is required. */
    allow_any_audience?: boolean;
    /** Accept any issuer; otherwise issuer is required. */
    allow_any_issuer?: boolean;
    /** The expected issuer. */
    issuer?: string;
    /** The expected audience. */
    audience?: string;
    /** The expected subject. */
    subject?: string;
    /** The largest token accepted, default 16384. */
    max_token_bytes?: number;
    /** The longest exp minus iat accepted, in seconds; unset by default. */
    max_lifetime?: number;
    /** Ids a built-in replay check refuses, for tests and simple stores. */
    seen_jti?: readonly string[];
    /** Require a cnf claim. */
    require_cnf?: boolean;
    /** Ignore a cnf claim, as for a bearer token. */
    ignore_cnf?: boolean;
    /** The holder proof text presented with the request. */
    proof?: string;
    /** The request the proof must be bound to. */
    request?: HolderRequest;
    /** The longest proof lifetime accepted, in seconds, default 60. */
    proof_lifetime?: number;
    /** Proof ids a built-in proof replay check refuses. */
    proof_seen_jti?: readonly string[];
    /** The replay check on jti, run inside the call; refusal is replayed. */
    replay?: ReplayCheck;
    /**
     * The replay check on the proof id, run inside the call when a proof
     * is given; refusal is proof_replayed. A proof with neither this nor
     * proof_seen_jti is rules_incomplete.
     */
    proofReplay?: ReplayCheck;
}

/** Raw cb2.local tokens: any bytes as the message. */
export interface LocalTokens {
    /** Seals msg under a key; the token text. */
    seal(key: LocalKey, msg: Bytes, footer?: OptionalBytes, implicit?: OptionalBytes): string;
    /** Opens a token; the message bytes. maxTokenBytes 0 means the default. */
    open(key: LocalKey, token: string, footer?: OptionalBytes, implicit?: OptionalBytes, maxTokenBytes?: number): Uint8Array;
}

/** Raw cb2.public tokens: any bytes as the message. */
export interface PublicTokens {
    /** Signs msg under a signing pair; the token text. */
    sign(key: SecretKey, msg: Bytes, footer?: OptionalBytes, implicit?: OptionalBytes): string;
    /** Verifies a token under the public half; the message bytes. */
    verify(key: PublicKey, token: string, footer?: OptionalBytes, implicit?: OptionalBytes, maxTokenBytes?: number): Uint8Array;
}

/** Claims tokens: claims in as an object, checked against rules on the way out. */
export interface ClaimsTokens {
    /** Seals claims under a local key; the key id goes into the footer. */
    seal(key: LocalKey, claims: Claims, implicit?: OptionalBytes): string;
    /** Signs claims under a signing pair; the key id goes into the footer. */
    sign(key: SecretKey, claims: Claims, implicit?: OptionalBytes): string;
    /** Opens a sealed token under the rules; the claims, or a Cb2Error. */
    open(token: string, key: LocalKey, rules: Rules, implicit?: OptionalBytes): Claims;
    /** Verifies a signed token under the rules; the claims, or a Cb2Error. */
    verify(token: string, key: PublicKey, rules: Rules, implicit?: OptionalBytes): Claims;
    /** The key id the footer names, unverified, to pick a key; null when none. */
    peekKeyId(token: string): string | null;
}

/** Holder proofs: the client's proof that it holds the key in cnf. */
export interface HolderProofs {
    /**
     * A public-mode proof by the client's signing pair for one request and
     * one access token. now defaults to the clock, lifetime to 60 seconds.
     */
    prove(clientSecret: SecretKey, request: HolderRequest, accessToken: string, jti: string, now?: number, lifetime?: number): string;
    /**
     * A local-mode proof under the kcb2.local proof key the issuer put in
     * cnf of a cb2.local access token.
     */
    proveLocal(proofKey: LocalKey, request: HolderRequest, accessToken: string, jti: string, now?: number, lifetime?: number): string;
    /** The normalized request target; throws argument when it is not a URI. */
    normalizeTarget(uri: string): string;
}

/** kcb2.local-wrap: a local key wrapped under another. */
export interface KeyWrapping {
    /** Wraps key under wrapping; the kcb2.local-wrap text. */
    wrap(wrapping: LocalKey, key: LocalKey): string;
    /** Unwraps the text with the wrapping key; a new local key. */
    unwrap(text: string, wrapping: LocalKey): LocalKey;
}

/** kcb2.seal: a local key sealed to a recipient with X-Wing. */
export interface KeySealing {
    /** Seals key to the recipient; the kcb2.seal text. */
    seal(to: RecipientPublicKey, key: LocalKey): string;
    /** Unseals the text with the recipient pair; a new local key. */
    unseal(text: string, by: RecipientKey): LocalKey;
}

/**
 * The Emscripten module under the API: the C ABI as `_cb2_*` functions
 * over the wasm heap, for callers who need it raw. The contract of each
 * function is in bindings/c/include/cb2_c.h.
 */
export interface Cb2Core {
    /** The wasm heap. */
    readonly HEAPU8: Uint8Array;
    _malloc(size: number): number;
    _free(ptr: number): void;
    UTF8ToString(ptr: number, maxBytesToRead?: number): string;
    stringToUTF8(text: string, ptr: number, maxBytesToWrite: number): number;
    lengthBytesUTF8(text: string): number;
    getValue(ptr: number, type: string): number;
    setValue(ptr: number, value: number, type: string): void;
    addFunction(fn: (...args: number[]) => number | void, signature: string): number;
    removeFunction(index: number): void;
    ccall(name: string, returnType: string | null, argTypes: string[], args: unknown[]): unknown;
    cwrap(name: string, returnType: string | null, argTypes: string[]): (...args: unknown[]) => unknown;
    /*
     * Every function of bindings/c/include/cb2_c.h, prefixed with an
     * underscore: pointers, sizes and int are numbers, int64_t is a
     * bigint, and a function pointer is a wasm table index from
     * addFunction.
     */
    _cb2_version(): number;
    _cb2_abi_version(): number;
    _cb2_has_public(): number;
    _cb2_has_seal(): number;
    _cb2_error_name(code: number): number;
    _cb2_free(p: number): void;
    _cb2_free_secret(s: number): void;
    _cb2_local_key_generate(out: number): number;
    _cb2_local_key_from_bytes(bytes: number, len: number, out: number): number;
    _cb2_local_key_from_paserk(text: number, len: number, out: number): number;
    _cb2_local_key_to_paserk(key: number): number;
    _cb2_local_key_paserk_id(key: number): number;
    _cb2_local_key_key_id(key: number): number;
    _cb2_local_key_set_key_id(key: number, id: number, len: number): number;
    _cb2_local_key_clear_key_id(key: number): void;
    _cb2_local_key_free(key: number): void;
    _cb2_secret_key_generate(out: number): number;
    _cb2_secret_key_from_bytes(bytes: number, len: number, out: number): number;
    _cb2_secret_key_from_paserk(text: number, len: number, out: number): number;
    _cb2_secret_key_to_paserk(key: number): number;
    _cb2_secret_key_public_key(key: number, out: number): number;
    _cb2_secret_key_key_id(key: number): number;
    _cb2_secret_key_set_key_id(key: number, id: number, len: number): number;
    _cb2_secret_key_clear_key_id(key: number): void;
    _cb2_secret_key_free(key: number): void;
    _cb2_public_key_from_bytes(bytes: number, len: number, out: number): number;
    _cb2_public_key_from_paserk(text: number, len: number, out: number): number;
    _cb2_public_key_to_paserk(key: number): number;
    _cb2_public_key_paserk_id(key: number): number;
    _cb2_public_key_key_id(key: number): number;
    _cb2_public_key_set_key_id(key: number, id: number, len: number): number;
    _cb2_public_key_clear_key_id(key: number): void;
    _cb2_public_key_free(key: number): void;
    _cb2_recipient_key_generate(out: number): number;
    _cb2_recipient_key_from_bytes(bytes: number, len: number, out: number): number;
    _cb2_recipient_key_from_paserk(text: number, len: number, out: number): number;
    _cb2_recipient_key_to_paserk(key: number): number;
    _cb2_recipient_key_public_key(key: number, out: number): number;
    _cb2_recipient_key_paserk_id(key: number): number;
    _cb2_recipient_key_free(key: number): void;
    _cb2_recipient_public_key_from_bytes(bytes: number, len: number, out: number): number;
    _cb2_recipient_public_key_from_paserk(text: number, len: number, out: number): number;
    _cb2_recipient_public_key_to_paserk(key: number): number;
    _cb2_recipient_public_key_paserk_id(key: number): number;
    _cb2_recipient_public_key_free(key: number): void;
    _cb2_local_seal(key: number, msg: number, msgLen: number, footer: number, footerLen: number, implicit: number, implicitLen: number, outToken: number, outLen: number): number;
    _cb2_local_open(key: number, token: number, tokenLen: number, footer: number, footerLen: number, implicit: number, implicitLen: number, maxTokenBytes: number, outMsg: number, outLen: number): number;
    _cb2_public_sign(key: number, msg: number, msgLen: number, footer: number, footerLen: number, implicit: number, implicitLen: number, outToken: number, outLen: number): number;
    _cb2_public_verify(key: number, token: number, tokenLen: number, footer: number, footerLen: number, implicit: number, implicitLen: number, maxTokenBytes: number, outMsg: number, outLen: number): number;
    _cb2_token_seal(key: number, claimsJson: number, claimsLen: number, implicit: number, implicitLen: number, outToken: number, outLen: number): number;
    _cb2_token_sign(key: number, claimsJson: number, claimsLen: number, implicit: number, implicitLen: number, outToken: number, outLen: number): number;
    _cb2_token_open(key: number, token: number, tokenLen: number, rulesJson: number, rulesLen: number, implicit: number, implicitLen: number, replay: number, proofReplay: number, user: number, outClaims: number, outLen: number): number;
    _cb2_token_verify(key: number, token: number, tokenLen: number, rulesJson: number, rulesLen: number, implicit: number, implicitLen: number, replay: number, proofReplay: number, user: number, outClaims: number, outLen: number): number;
    _cb2_peek_key_id(token: number, tokenLen: number, outId: number): number;
    _cb2_holder_prove(client: number, htm: number, htmLen: number, htu: number, htuLen: number, nonce: number, nonceLen: number, accessToken: number, accessLen: number, jti: number, jtiLen: number, now: bigint, lifetime: bigint, outProof: number, outLen: number): number;
    _cb2_holder_prove_local(proofKey: number, htm: number, htmLen: number, htu: number, htuLen: number, nonce: number, nonceLen: number, accessToken: number, accessLen: number, jti: number, jtiLen: number, now: bigint, lifetime: bigint, outProof: number, outLen: number): number;
    _cb2_holder_normalize_target(uri: number, len: number, out: number): number;
    _cb2_wrap(wrapping: number, key: number, out: number): number;
    _cb2_unwrap(text: number, len: number, wrapping: number, out: number): number;
    _cb2_seal(to: number, key: number, out: number): number;
    _cb2_unseal(text: number, len: number, by: number, out: number): number;
}

/** The API {@link load} resolves to, over one independent core. */
export interface Cb2 {
    /** cb2.local keys. */
    readonly LocalKey: GeneratedKeyConstructor<LocalKey>;
    /** cb2.public signing pairs; only when {@link Cb2.hasPublic}. */
    readonly SecretKey: GeneratedKeyConstructor<SecretKey>;
    /** cb2.public public halves. */
    readonly PublicKey: KeyConstructor<PublicKey>;
    /** kcb2.seal recipient pairs; only when {@link Cb2.hasSeal}. */
    readonly RecipientKey: GeneratedKeyConstructor<RecipientKey>;
    /** kcb2.seal recipient public halves. */
    readonly RecipientPublicKey: KeyConstructor<RecipientPublicKey>;
    /** Raw cb2.local tokens. */
    readonly Local: LocalTokens;
    /** Raw cb2.public tokens. */
    readonly Public: PublicTokens;
    /** Claims tokens under rules. */
    readonly Token: ClaimsTokens;
    /** Holder proofs. */
    readonly Holder: HolderProofs;
    /** kcb2.local-wrap. */
    readonly KeyWrap: KeyWrapping;
    /** kcb2.seal. */
    readonly Seal: KeySealing;
    /** The error class every refusal throws. */
    readonly Cb2Error: typeof Cb2Error;
    /** True when cb2.public (ML-DSA-65) is in this build. */
    hasPublic(): boolean;
    /** True when kcb2.seal (X-Wing) is in this build. */
    hasSeal(): boolean;
    /** The library version, such as "0.1.0". */
    version(): string;
    /** The stable name of an error code: "ok", a verdict name, or "unknown". */
    errorName(code: number): string;
    /** The Emscripten module itself. */
    readonly core: Cb2Core;
}

/**
 * Instantiates the WebAssembly core and resolves to the API over it. Each
 * call builds an independent core, with its own heap and key classes.
 */
export declare function load(options?: LoadOptions): Promise<Cb2>;
