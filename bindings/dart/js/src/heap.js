/**
 * The traffic across the wasm heap: inputs copied in for the length of one
 * call and released afterwards (wiped first when they carry key material),
 * results copied out and released with cb2_free or cb2_free_secret, and
 * the error codes turned into Cb2Error.
 */
import { Cb2Error } from "./error.js";

const encoder = new TextEncoder();

/**
 * Bytes for an argument: a Uint8Array as is, a string as UTF-8, and
 * undefined or null as empty.
 * @param {Uint8Array|string|undefined|null} value
 * @returns {Uint8Array}
 */
export function bytesOf(value) {
    if (value === undefined || value === null) return new Uint8Array(0);
    if (value instanceof Uint8Array) return value;
    if (typeof value === "string") return encoder.encode(value);
    throw new TypeError("expected a Uint8Array or a string");
}

/** The allocations of one call, released together. */
export class Arena {
    constructor(m) {
        this.m = m;
        this.blocks = [];
    }

    /**
     * Copies value into the heap. An empty value becomes the null pointer,
     * which the ABI reads as an empty span.
     * @returns {{ptr: number, len: number}}
     */
    bytes(value, secret = false) {
        const u8 = bytesOf(value);
        if (u8.length === 0) return { ptr: 0, len: 0 };
        const ptr = this.m._malloc(u8.length);
        if (ptr === 0) throw new Cb2Error(5, "internal");
        this.m.HEAPU8.set(u8, ptr);
        this.blocks.push({ ptr, len: u8.length, secret });
        return { ptr, len: u8.length };
    }

    /** A zeroed slot for a pointer or size_t result. */
    out() {
        const ptr = this.m._malloc(4);
        if (ptr === 0) throw new Cb2Error(5, "internal");
        this.m.setValue(ptr, 0, "i32");
        this.blocks.push({ ptr, len: 4, secret: false });
        return ptr;
    }

    /** The pointer stored in a slot from out(). */
    pointerAt(slot) {
        return this.m.getValue(slot, "*");
    }

    /** The size_t stored in a slot from out(). */
    sizeAt(slot) {
        return this.m.getValue(slot, "i32") >>> 0;
    }

    release() {
        for (const b of this.blocks) {
            if (b.secret) this.m.HEAPU8.fill(0, b.ptr, b.ptr + b.len);
            this.m._free(b.ptr);
        }
        this.blocks = [];
    }
}

/**
 * Runs fn with an arena that is released when fn returns or throws.
 * @template T
 * @param {object} m the core module
 * @param {(a: Arena) => T} fn
 * @returns {T}
 */
export function withArena(m, fn) {
    const a = new Arena(m);
    try {
        return fn(a);
    } finally {
        a.release();
    }
}

/** Throws the Cb2Error for a non-zero code. */
export function check(m, code) {
    if (code !== 0) throw new Cb2Error(code, m.UTF8ToString(m._cb2_error_name(code)));
}

/**
 * Takes a NUL-terminated text result and frees it; null for a null pointer.
 * @param {boolean} secret free with cb2_free_secret (wipe first)
 */
export function takeText(m, ptr, secret = false) {
    if (ptr === 0) return null;
    const text = m.UTF8ToString(ptr);
    if (secret) m._cb2_free_secret(ptr);
    if (!secret) m._cb2_free(ptr);
    return text;
}

/** Takes a byte result of len bytes as a fresh Uint8Array and frees it. */
export function takeBytes(m, ptr, len) {
    const bytes = m.HEAPU8.slice(ptr, ptr + len);
    m._cb2_free(ptr);
    return bytes;
}
