/**
 * The key classes over the opaque handles of the C ABI. Each class offers
 * what its ABI type offers:
 *
 *   LocalKey            generate, fromBytes, fromPaserk, toPaserk (secret),
 *                       paserkId, keyId, setKeyId, clearKeyId, free
 *   SecretKey           generate, fromBytes, fromPaserk, toPaserk (secret),
 *                       publicKey, keyId, setKeyId, clearKeyId, free
 *   PublicKey           fromBytes, fromPaserk, toPaserk, paserkId, keyId,
 *                       setKeyId, clearKeyId, free
 *   RecipientKey        generate, fromBytes, fromPaserk, toPaserk (secret),
 *                       publicKey, paserkId, free
 *   RecipientPublicKey  fromBytes, fromPaserk, toPaserk, paserkId, free
 *
 * A key's handle lives until free(); using a freed key throws. The bytes
 * and PASERK text given to the secret constructors are wiped from the wasm
 * heap after the copy, and the PASERK of a secret is freed with
 * cb2_free_secret.
 */
import { check, takeText, withArena } from "./heap.js";

const SPECS = {
    LocalKey: { prefix: "local_key", secret: true, generate: true, paserkId: true, keyId: true },
    SecretKey: { prefix: "secret_key", secret: true, generate: true, keyId: true, publicKey: "PublicKey" },
    PublicKey: { prefix: "public_key", secret: false, paserkId: true, keyId: true },
    RecipientKey: { prefix: "recipient_key", secret: true, generate: true, paserkId: true, publicKey: "RecipientPublicKey" },
    RecipientPublicKey: { prefix: "recipient_public_key", secret: false, paserkId: true },
};

function construct(m, fn, input, secret) {
    return withArena(m, (a) => {
        const data = a.bytes(input, secret);
        const slot = a.out();
        check(m, fn(data.ptr, data.len, slot));
        return a.pointerAt(slot);
    });
}

function keyClass(m, name, spec) {
    const fn = (suffix) => m[`_cb2_${spec.prefix}_${suffix}`];
    class Key {
        #ptr;

        /** Wraps a handle the ABI returned; the static constructors are the public way in. */
        constructor(ptr) {
            this.#ptr = ptr;
        }

        /** The handle; throws once the key is freed. */
        get ptr() {
            if (this.#ptr === 0) throw new Error(`${name} was freed`);
            return this.#ptr;
        }

        /** True once free() ran. */
        get freed() {
            return this.#ptr === 0;
        }

        /** A key from its raw bytes (argument when they are not acceptable). */
        static fromBytes(bytes) {
            return new this(construct(m, fn("from_bytes"), bytes, spec.secret));
        }

        /** A key from its PASERK text. */
        static fromPaserk(text) {
            return new this(construct(m, fn("from_paserk"), text, spec.secret));
        }

        /** The PASERK text of the key. */
        toPaserk() {
            return takeText(m, fn("to_paserk")(this.ptr), spec.secret);
        }

        /** Releases the handle; safe to call twice. */
        free() {
            if (this.#ptr === 0) return;
            fn("free")(this.#ptr);
            this.#ptr = 0;
        }
    }
    Object.defineProperty(Key, "name", { value: name });
    if (spec.generate) Key.generate = function generate() {
        return new this(withArena(m, (a) => {
            const slot = a.out();
            check(m, fn("generate")(slot));
            return a.pointerAt(slot);
        }));
    };
    if (spec.paserkId) Key.prototype.paserkId = function paserkId() {
        return takeText(m, fn("paserk_id")(this.ptr));
    };
    if (spec.keyId) installKeyId(m, Key, fn);
    return Key;
}

function installKeyId(m, Key, fn) {
    Object.defineProperty(Key.prototype, "keyId", {
        get() {
            return takeText(m, fn("key_id")(this.ptr));
        },
        configurable: true,
    });
    Key.prototype.setKeyId = function setKeyId(id) {
        withArena(m, (a) => {
            const text = a.bytes(id);
            check(m, fn("set_key_id")(this.ptr, text.ptr, text.len));
        });
        return this;
    };
    Key.prototype.clearKeyId = function clearKeyId() {
        fn("clear_key_id")(this.ptr);
        return this;
    };
}

function installPublicKey(m, Key, Public, prefix) {
    Key.prototype.publicKey = function publicKey() {
        return new Public(withArena(m, (a) => {
            const slot = a.out();
            check(m, m[`_cb2_${prefix}_public_key`](this.ptr, slot));
            return a.pointerAt(slot);
        }));
    };
}

/**
 * Builds the five key classes over a core module.
 * @param {object} m the core module
 */
export function makeKeys(m) {
    const classes = {};
    for (const [name, spec] of Object.entries(SPECS)) classes[name] = keyClass(m, name, spec);
    for (const [name, spec] of Object.entries(SPECS)) {
        if (spec.publicKey) installPublicKey(m, classes[name], classes[spec.publicKey], spec.prefix);
    }
    return classes;
}
