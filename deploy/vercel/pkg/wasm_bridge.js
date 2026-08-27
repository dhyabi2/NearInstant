/* @ts-self-types="./wasm_bridge.d.ts" */

export class BrowserDkg {
    static __wrap(ptr) {
        const obj = Object.create(BrowserDkg.prototype);
        obj.__wbg_ptr = ptr;
        BrowserDkgFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserDkgFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserdkg_free(ptr, 0);
    }
    /**
     * The joint account once the DKG has finished (hex `nano_…` account is
     * derivable from these 32 bytes).
     * @returns {Uint8Array | undefined}
     */
    account() {
        const ret = wasm.browserdkg_account(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * This party's serialized key package (its OWN secret share) — feed it,
     * with `public_key_package`, into a `BrowserSigner` to sign or adaptor-
     * pre-sign. Available only after the DKG has finished.
     * @returns {Uint8Array | undefined}
     */
    key_package() {
        const ret = wasm.browserdkg_key_package(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Begin the DKG (runs part1). `my_id`/`their_id` are the two party ids
     * (1 and 2, opposite on each side).
     * @param {number} my_id
     * @param {number} their_id
     */
    constructor(my_id, their_id) {
        const ret = wasm.browserdkg_new(my_id, their_id);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        BrowserDkgFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Deterministic DKG for reproducible per-session joint accounts: identical
     * to `new` but seeds part1's randomness from a 32-byte session seed
     * (derive it from your wallet seed + a unique session id). part2/part3 are
     * already pure, so the whole DKG — and thus the joint account — is a
     * deterministic function of the two seeds. SAFE: this fixes the long-term
     * KEY SHARES (like an HD wallet), never the per-signature nonces, which
     * stay fresh (see `sign_commit`). Reuse a seed only with a unique session
     * id so every swap gets its own account.
     * @param {number} my_id
     * @param {number} their_id
     * @param {Uint8Array} seed
     * @returns {BrowserDkg}
     */
    static newSeeded(my_id, their_id, seed) {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserdkg_newSeeded(my_id, their_id, ptr0, len0);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BrowserDkg.__wrap(ret[0]);
    }
    /**
     * The shared public key package (same on both parties). Feed it into a
     * `BrowserSigner`. Available only after the DKG has finished.
     * @returns {Uint8Array | undefined}
     */
    public_key_package() {
        const ret = wasm.browserdkg_public_key_package(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * Our round-1 package to send to the peer.
     * @returns {Uint8Array}
     */
    round1_out() {
        const ret = wasm.browserdkg_round1_out(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Our round-2 package to send to the peer.
     * @returns {Uint8Array}
     */
    round2_out() {
        const ret = wasm.browserdkg_round2_out(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Feed the peer's round-1 package; runs part2 and prepares our round-2
     * package (fetch it with `round2_out`).
     * @param {Uint8Array} bytes
     */
    set_peer_round1(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserdkg_set_peer_round1(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Feed the peer's round-2 package; runs part3 and returns the 32-byte
     * joint Nano account both parties share.
     * @param {Uint8Array} bytes
     * @returns {Uint8Array}
     */
    set_peer_round2(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserdkg_set_peer_round2(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
}
if (Symbol.dispose) BrowserDkg.prototype[Symbol.dispose] = BrowserDkg.prototype.free;

/**
 * Stage-3 browser ceremony: a step-driven 2-of-2 FROST signer and adaptor
 * pre-signer, each party holding ONLY its own share. Seeded from a finished
 * `BrowserDkg` (`key_package()` + `public_key_package()`), it lets a browser
 * jointly sign Nano blocks (the open + guard rungs) and produce the adaptor
 * pre-signature for the claim — the cryptographic core of a helper-free swap.
 *
 * One round at a time. Plain signing: `sign_commit` → exchange → `sign_share`
 * → exchange → `aggregate_sig`. Adaptor pre-sign: `presign_commit` (with the
 * adaptor point) → exchange → `presign_share` → exchange → `aggregate_presig`.
 * The JS side shuttles the opaque byte blobs over the MailboxWire.
 */
export class BrowserSigner {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserSignerFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browsersigner_free(ptr, 0);
    }
    /**
     * The 32-byte joint Nano account (verifying key).
     * @returns {Uint8Array}
     */
    account() {
        const ret = wasm.browsersigner_account(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Aggregate the adaptor shares into a 96-byte pre-signature
     * (`r_adapted ‖ s_hat ‖ adaptor_point`).
     * @returns {Uint8Array}
     */
    aggregate_presig() {
        const ret = wasm.browsersigner_aggregate_presig(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Aggregate the plain shares into the 64-byte Nano-valid joint signature.
     * @returns {Uint8Array}
     */
    aggregate_sig() {
        const ret = wasm.browsersigner_aggregate_sig(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Build a signer from a finished DKG's serialized key material.
     * @param {Uint8Array} key_package
     * @param {Uint8Array} public_key_package
     * @param {number} _my_id
     * @param {number} their_id
     */
    constructor(key_package, public_key_package, _my_id, their_id) {
        const ptr0 = passArray8ToWasm0(key_package, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(public_key_package, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browsersigner_new(ptr0, len0, ptr1, len1, _my_id, their_id);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        BrowserSignerFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Begin an adaptor pre-signing round on `message` for `adaptor_point`
     * (`T = x·G`, 32 bytes).
     * @param {Uint8Array} message
     * @param {Uint8Array} adaptor_point
     * @returns {Uint8Array}
     */
    presign_commit(message, adaptor_point) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(adaptor_point, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browsersigner_presign_commit(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * Produce our adaptor signature share (also kept for aggregation).
     *
     * CONSUMES the round's nonces (`take()`) for the same reason as
     * `sign_share`: single-use per nonce pair, or the secret share leaks.
     * @returns {Uint8Array}
     */
    presign_share() {
        const ret = wasm.browsersigner_presign_share(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Feed the peer's commitment (from either commit step).
     * @param {Uint8Array} bytes
     */
    set_peer_commit(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsersigner_set_peer_commit(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Feed the peer's signature share (plain or adaptor).
     * @param {Uint8Array} bytes
     */
    set_peer_share(bytes) {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsersigner_set_peer_share(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * Begin a plain signing round on `message` (a 32-byte block hash).
     * @param {Uint8Array} message
     * @returns {Uint8Array}
     */
    sign_commit(message) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browsersigner_sign_commit(this.__wbg_ptr, ptr0, len0);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v2;
    }
    /**
     * Produce our plain signature share (also kept for aggregation).
     *
     * CONSUMES the round's nonces (`take()`): a FROST signing nonce pair must
     * sign exactly ONE message. Producing a second share from the same nonces
     * against a different peer commitment yields a solvable linear system that
     * recovers our long-term secret share, so a second call here fails closed
     * ("call sign_commit first") rather than reusing the nonce.
     * @returns {Uint8Array}
     */
    sign_share() {
        const ret = wasm.browsersigner_sign_share(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) BrowserSigner.prototype[Symbol.dispose] = BrowserSigner.prototype.free;

/**
 * Argon2id as a raw 32-byte key-derivation function (NOT reduced to a curve
 * scalar): the wallet uses this to derive an AES-256-GCM key that encrypts the
 * random wallet seed at rest. Same memory-hard parameters as `argon2id_seed`
 * (OWASP floor 19 MiB, t=2, p=1; `mem_kib` may raise it). `salt` ≥ 8 bytes.
 * Returns the full 32-byte tag, or an empty vec on bad input.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} mem_kib
 * @returns {Uint8Array}
 */
export function argon2id_raw(passphrase, salt, mem_kib) {
    const ptr0 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.argon2id_raw(ptr0, len0, ptr1, len1, mem_kib);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Stage 6 custody: stretch a human passphrase into a 32-byte wallet seed with
 * Argon2id (memory-hard — a stolen page or shoulder-surfed passphrase still
 * costs the attacker the full KDF per guess). Runs inside a Web Worker whose
 * scope the DOM cannot read, so the seed never touches the page. `salt` must
 * be ≥ 8 bytes and STABLE for an account (store it, e.g. localStorage). Params
 * are the OWASP-recommended Argon2id floor (19 MiB, t=2, p=1); `mem_kib` may
 * raise the memory cost. Returns the 32-byte seed (feed to `seed_account` /
 * `sign_state_block`), or an empty vec on bad input.
 * @param {string} passphrase
 * @param {Uint8Array} salt
 * @param {number} mem_kib
 * @returns {Uint8Array}
 */
export function argon2id_seed(passphrase, salt, mem_kib) {
    const ptr0 = passStringToWasm0(passphrase, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(salt, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.argon2id_seed(ptr0, len0, ptr1, len1, mem_kib);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Run one real atomic chunk (Nano leg) and return a JSON string of every
 * artifact. Takes ~a few ms of curve math plus demo PoW.
 * @param {bigint} chunk_raw
 * @returns {string}
 */
export function atomic_chunk_demo(chunk_raw) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.atomic_chunk_demo(chunk_raw);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * The deterministic burn account (32 bytes) for a market side.
 * `side`: 0 = sell XNO, 1 = sell XMR. Mirrors `dex_core::beacon::namespace_account`.
 * @param {string} pair
 * @param {number} side
 * @returns {Uint8Array}
 */
export function beacon_account(pair, side) {
    const ptr0 = passStringToWasm0(pair, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.beacon_account(ptr0, len0, side);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * The namespace account as a `nano_…` address (what the receivable RPC takes).
 * @param {string} pair
 * @param {number} side
 * @returns {string}
 */
export function beacon_address(pair, side) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(pair, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.beacon_address(ptr0, len0, side);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Decode a receivable raw amount (decimal string) back into an intent as
 * JSON `{"side":n,"price_e9":n,"size_log2":n}`, or empty string for anything
 * that is not beacon-encoded (junk dust, bad checksum, wrong version).
 * @param {string} amount_raw
 * @returns {string}
 */
export function beacon_decode(amount_raw) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(amount_raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.beacon_decode(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Encode an order intent into the raw dust amount (decimal string, < 2^64).
 * Empty string if `price_e9` overflows its 40-bit field.
 * @param {number} side
 * @param {bigint} price_e9
 * @param {number} size_log2
 * @returns {string}
 */
export function beacon_encode(side, price_e9, size_log2) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.beacon_encode(side, price_e9, size_log2);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Version tag for the UI.
 * @returns {string}
 */
export function engine_version() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.engine_version();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * @returns {string}
 */
export function escrow_selftest() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.escrow_selftest();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Generate a fresh adaptor secret `x` and its point `T = x·G` (32 ‖ 32 bytes).
 * In a real swap the XMR-seller does this: `T` becomes the adaptor point (its
 * Monero spend key), and revealing `x` by completing the Nano claim is what
 * hands the sweep secret to the counterparty. Exposed so the browser side that
 * owns the Monero key can produce the pair.
 * @returns {Uint8Array}
 */
export function gen_adaptor() {
    const ret = wasm.gen_adaptor();
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * A persistent browser identity: a fresh ed25519 key pair returned as
 * `{"seed": <hex32>, "pubkey": <hex32>}`. The caller stores the seed (e.g. in
 * localStorage) and passes it to `make_order_seeded` / `make_pof` so the maker
 * keeps ONE identity across orders instead of a throwaway key per order.
 * @returns {string}
 */
export function gen_identity() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.gen_identity();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Sign a specific order (side 0=sell XNO, 1=sell XMR) with the given amount
 * in milli-XNO and rate in micro (XMR-per-XNO × 1e6). `now_secs` is the JS
 * wall clock (seconds); the order expires `now_secs + ORDER_TTL_SECS`.
 * Returns hex wire bytes, or an empty string if the amount would overflow.
 * Same canonical encoding as dex_core::order.
 * @param {number} side
 * @param {bigint} amount_milli_xno
 * @param {bigint} rate_micro
 * @param {bigint} nonce
 * @param {bigint} now_secs
 * @returns {string}
 */
export function make_order(side, amount_milli_xno, rate_micro, nonce, now_secs) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.make_order(side, amount_milli_xno, rate_micro, nonce, now_secs);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Sign an order with the identity seed and an explicit `pof_hash` (from
 * `make_pof`), so the order carries a REAL proof-of-funds commitment instead
 * of the `NO_POF` sentinel. `side` 0 = sell XNO, 1 = sell XMR; `amount_milli_xno`
 * is milli-XNO; `rate_micro` is XMR-per-XNO × 1e6. Returns hex wire bytes.
 * @param {string} seed_hex
 * @param {number} side
 * @param {bigint} amount_milli_xno
 * @param {bigint} rate_micro
 * @param {bigint} nonce
 * @param {bigint} now_secs
 * @param {string} pof_hash_hex
 * @returns {string}
 */
export function make_order_seeded(seed_hex, side, amount_milli_xno, rate_micro, nonce, now_secs, pof_hash_hex) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(pof_hash_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.make_order_seeded(ptr0, len0, side, amount_milli_xno, rate_micro, nonce, now_secs, ptr1, len1);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Sign a Nano proof-of-funds with the identity seed: a statement that the
 * account controls at least `amount_raw` (decimal string, raw units). Returns
 * `{"hash": <hex32>, "wire": <hex>}` — `hash` is the value to put in the
 * order's `pof_hash` field; `wire` is the signed proof (gossiped beside the
 * order via the peer `0x02` frame). Format matches `dex_core::pof::NanoFundsProof`.
 * @param {string} seed_hex
 * @param {string} amount_raw
 * @param {bigint} as_of_block
 * @param {bigint} expires
 * @param {bigint} nonce
 * @returns {string}
 */
export function make_pof(seed_hex, amount_raw, as_of_block, expires, nonce) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(amount_raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.make_pof(ptr0, len0, ptr1, len1, as_of_block, expires, nonce);
        deferred3_0 = ret[0];
        deferred3_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Produce a real signed order (ed25519-blake2b) as hex wire bytes, for the
 * browser to gossip to the live relay. Inlines the dex-core order wire
 * format so the wasm stays light (signing crate only, no Monero deps).
 * @param {bigint} now_secs
 * @returns {string}
 */
export function make_test_order(now_secs) {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.make_test_order(now_secs);
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}

/**
 * Verify a completed 64-byte signature as a real Nano signature for
 * `account` over `message`.
 * Sign an arbitrary message with the ed25519-blake2b key derived from
 * `seed_hex` (the same key as the Nano account for that seed). The signature
 * verifies with `nano_check(account, message, sig)`. Used to AUTHENTICATE the
 * rendezvous handshake: the maker signs (offer hash || its ephemeral pubkey)
 * so a taker can bind the reply to the account that posted the offer, closing
 * the unauthenticated-ECDH MITM window. Returns 64 bytes, or empty on failure.
 * @param {string} seed_hex
 * @param {Uint8Array} message
 * @returns {Uint8Array}
 */
export function msg_sign(seed_hex, message) {
    const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.msg_sign(ptr0, len0, ptr1, len1);
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Decode a `nano_…`/`xrb_…` address to its 32-byte public key (empty on error).
 * @param {string} addr
 * @returns {Uint8Array}
 */
export function nano_address_decode(addr) {
    const ptr0 = passStringToWasm0(addr, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.nano_address_decode(ptr0, len0);
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Encode a 32-byte public key as a `nano_…` address (empty on bad length).
 * @param {Uint8Array} public_key
 * @returns {string}
 */
export function nano_address_encode(public_key) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passArray8ToWasm0(public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.nano_address_encode(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * @param {Uint8Array} account
 * @param {Uint8Array} message
 * @param {Uint8Array} signature
 * @returns {boolean}
 */
export function nano_check(account, message, signature) {
    const ptr0 = passArray8ToWasm0(account, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.nano_check(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * Self-test the I1 puzzle-escrow refund backstop in the browser: escrow a random
 * scalar share across `m` RSW time-lock instances, run the cut-and-choose audit,
 * verify, then SOLVE each kept puzzle and confirm the recovered scalar matches
 * the original. Proves the time-lock refund primitive compiles and runs in wasm
 * (num-bigint-dig modular exponentiation) without any counterparty. Small,
 * fast params (m=8, 130-bit primes, t=512); returns a JSON status.
 * Self-test the bilateral grief-bond (H-series) in the browser: build a 2-of-2
 * bond, pre-sign both parties' early-exit chains, and verify them. This is the
 * anti-grief primitive that lets an always-on maker be safe (a griefer forfeits
 * their bond to the victim). Proves it compiles and runs in wasm.
 * @returns {boolean}
 */
export function pledge_selftest() {
    const ret = wasm.pledge_selftest();
    return ret !== 0;
}

/**
 * Complete a 96-byte pre-signature with the 32-byte adaptor secret `x`,
 * yielding the 64-byte Nano wire signature. Broadcasting it reveals `x`.
 * @param {Uint8Array} presig
 * @param {Uint8Array} secret
 * @returns {Uint8Array}
 */
export function presig_complete(presig, secret) {
    const ptr0 = passArray8ToWasm0(presig, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.presig_complete(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Extract the adaptor secret `x` from a broadcast signature and the
 * pre-signature it completed (`x = s − ŝ`). This is how the XNO-seller learns
 * the Monero sweep secret the instant the claim is published.
 * @param {Uint8Array} presig
 * @param {Uint8Array} signature
 * @returns {Uint8Array}
 */
export function presig_extract(presig, signature) {
    const ptr0 = passArray8ToWasm0(presig, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(signature, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.presig_extract(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * Verify the adaptor relation of a pre-signature against the joint `account`
 * and 32-byte message — provable from public data alone.
 * @param {Uint8Array} presig
 * @param {Uint8Array} account
 * @param {Uint8Array} message
 * @returns {boolean}
 */
export function presig_verify(presig, account, message) {
    const ptr0 = passArray8ToWasm0(presig, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(account, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.presig_verify(ptr0, len0, ptr1, len1, ptr2, len2);
    return ret !== 0;
}

/**
 * The identity seed's public half as JSON `{"pubkey":hex,"address":"nano_…"}`
 * — a browser identity IS a Nano account; fund it to publish beacons.
 * @param {string} seed_hex
 * @returns {string}
 */
export function seed_account(seed_hex) {
    let deferred2_0;
    let deferred2_1;
    try {
        const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.seed_account(ptr0, len0);
        deferred2_0 = ret[0];
        deferred2_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
    }
}

/**
 * Build and sign a Nano state block with the identity seed (single-key
 * account — used for beacon publishes and pocketing dust; joint 2-of-2 blocks
 * go through `BrowserSigner`). Inputs are hex/decimal strings; `subtype` is
 * one of open|receive|send|change. Returns the full `process` RPC body as
 * JSON (work left as the placeholder `"WORK"` for the caller to fill) plus
 * `hash` and `work_root`, or empty string on bad input.
 * @param {string} seed_hex
 * @param {string} previous_hex
 * @param {string} representative_hex
 * @param {string} balance_raw
 * @param {string} link_hex
 * @param {string} subtype
 * @returns {string}
 */
export function sign_state_block(seed_hex, previous_hex, representative_hex, balance_raw, link_hex, subtype) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(seed_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(previous_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(representative_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(balance_raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(link_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(subtype, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.sign_state_block(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        deferred7_0 = ret[0];
        deferred7_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * The canonical 32-byte hash of a Nano state block, without signing it. The
 * swap driver needs this to bind the adaptor pre-signature to the REAL claim
 * block both parties agree on (the send that pays the XMR-seller their XNO),
 * rather than an arbitrary message. Same field encoding as `sign_state_block`.
 * @param {string} account_hex
 * @param {string} previous_hex
 * @param {string} representative_hex
 * @param {string} balance_raw
 * @param {string} link_hex
 * @param {string} subtype
 * @returns {Uint8Array}
 */
export function state_block_hash(account_hex, previous_hex, representative_hex, balance_raw, link_hex, subtype) {
    const ptr0 = passStringToWasm0(account_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(previous_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(representative_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(balance_raw, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(link_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ptr5 = passStringToWasm0(subtype, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len5 = WASM_VECTOR_LEN;
    const ret = wasm.state_block_hash(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
    var v7 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v7;
}

/**
 * Validate a work nonce against a threshold (mirror of the node's check).
 * @param {Uint8Array} root
 * @param {bigint} nonce
 * @param {bigint} threshold
 * @returns {boolean}
 */
export function work_check(root, nonce, threshold) {
    const ptr0 = passArray8ToWasm0(root, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.work_check(ptr0, len0, nonce, threshold);
    return ret !== 0;
}

/**
 * Search `count` nonces from `start` for work over `root` meeting `threshold`.
 * Returns the nonce or `undefined` — the browser calls this in chunks from an
 * async loop (or a Worker) so the UI stays alive; the found nonce is verified
 * by any Nano node exactly like node-generated work.
 * @param {Uint8Array} root
 * @param {bigint} threshold
 * @param {bigint} start
 * @param {bigint} count
 * @returns {bigint | undefined}
 */
export function work_search(root, threshold, start, count) {
    const ptr0 = passArray8ToWasm0(root, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.work_search(ptr0, len0, threshold, start, count);
    return ret[0] === 0 ? undefined : BigInt.asUintN(64, ret[1]);
}

/**
 * Nano mainnet work thresholds, as hex strings the JS side can hold as BigInt.
 * @returns {string}
 */
export function work_thresholds() {
    let deferred1_0;
    let deferred1_1;
    try {
        const ret = wasm.work_thresholds();
        deferred1_0 = ret[0];
        deferred1_1 = ret[1];
        return getStringFromWasm0(ret[0], ret[1]);
    } finally {
        wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_is_function_5e4570eb24ffa122: function(arg0) {
            const ret = typeof(arg0) === 'function';
            return ret;
        },
        __wbg___wbindgen_is_object_a2790eb24c211ea0: function(arg0) {
            const val = arg0;
            const ret = typeof(val) === 'object' && val !== null;
            return ret;
        },
        __wbg___wbindgen_is_string_e6f02f0ea5f20a32: function(arg0) {
            const ret = typeof(arg0) === 'string';
            return ret;
        },
        __wbg___wbindgen_is_undefined_6cff064c44e0d823: function(arg0) {
            const ret = arg0 === undefined;
            return ret;
        },
        __wbg___wbindgen_throw_bb96b2010945f0bc: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_call_35dba3c747ad7521: function() { return handleError(function (arg0, arg1, arg2) {
            const ret = arg0.call(arg1, arg2);
            return ret;
        }, arguments); },
        __wbg_crypto_38df2bab126b63dc: function(arg0) {
            const ret = arg0.crypto;
            return ret;
        },
        __wbg_getRandomValues_c44a50d8cfdaebeb: function() { return handleError(function (arg0, arg1) {
            arg0.getRandomValues(arg1);
        }, arguments); },
        __wbg_length_36bd29c6848c2144: function(arg0) {
            const ret = arg0.length;
            return ret;
        },
        __wbg_msCrypto_bd5a034af96bcba6: function(arg0) {
            const ret = arg0.msCrypto;
            return ret;
        },
        __wbg_new_with_length_3ffc1c56427c525c: function(arg0) {
            const ret = new Uint8Array(arg0 >>> 0);
            return ret;
        },
        __wbg_node_84ea875411254db1: function(arg0) {
            const ret = arg0.node;
            return ret;
        },
        __wbg_process_44c7a14e11e9f69e: function(arg0) {
            const ret = arg0.process;
            return ret;
        },
        __wbg_prototypesetcall_de8e0d9553586985: function(arg0, arg1, arg2) {
            Uint8Array.prototype.set.call(getArrayU8FromWasm0(arg0, arg1), arg2);
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_static_accessor_GLOBAL_THIS_466428f93b4eaa76: function() {
            const ret = typeof globalThis === 'undefined' ? null : globalThis;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_GLOBAL_c7aea38d4de089bc: function() {
            const ret = typeof global === 'undefined' ? null : global;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_SELF_42d4fae05e59267a: function() {
            const ret = typeof self === 'undefined' ? null : self;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_static_accessor_WINDOW_e0db14a0eba6a812: function() {
            const ret = typeof window === 'undefined' ? null : window;
            return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
        },
        __wbg_subarray_a4cc58201c7359fd: function(arg0, arg1, arg2) {
            const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./wasm_bridge_bg.js": import0,
    };
}

const BrowserDkgFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserdkg_free(ptr, 1));
const BrowserSignerFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browsersigner_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('wasm_bridge_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
