/* @ts-self-types="./wasm_monero.d.ts" */

/**
 * A connected Monero daemon, everything routed through the JS fetch.
 */
class XmrNode {
    static __wrap(ptr) {
        const obj = Object.create(XmrNode.prototype);
        obj.__wbg_ptr = ptr;
        XmrNodeFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        XmrNodeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_xmrnode_free(ptr, 0);
    }
    /**
     * Connect (probes the daemon once). `post_fn(route, body) -> Promise<Uint8Array>`.
     * @param {Function} post_fn
     * @returns {Promise<XmrNode>}
     */
    static connect(post_fn) {
        const ret = wasm.xmrnode_connect(post_fn);
        return ret;
    }
    /**
     * Current chain height (the number of the next block).
     * @returns {Promise<number>}
     */
    height() {
        const ret = wasm.xmrnode_height(this.__wbg_ptr);
        return ret;
    }
    /**
     * Broadcast a signed transaction (hex). Returns its hash.
     * @param {string} tx_hex
     * @returns {Promise<string>}
     */
    publish(tx_hex) {
        const ptr0 = passStringToWasm0(tx_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.xmrnode_publish(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * View-key scan of blocks `[from, to]` (inclusive, descending) for
     * outputs paid to the joint address. Returns JSON
     * `{block, amount, output}` (output = hex WalletOutput, spendable
     * input to `sweep_sign`) for the first hit, or `null`. `on_block`,
     * if given, is called with each block number scanned.
     * @param {Uint8Array} spend_pub
     * @param {Uint8Array} view_key
     * @param {number} from
     * @param {number} to
     * @param {Function | null} [on_block]
     * @returns {Promise<any>}
     */
    scan(spend_pub, view_key, from, to, on_block) {
        const ptr0 = passArray8ToWasm0(spend_pub, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(view_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.xmrnode_scan(this.__wbg_ptr, ptr0, len0, ptr1, len1, from, to, isLikeNone(on_block) ? 0 : addToExternrefTable0(on_block));
        return ret;
    }
    /**
     * View-key scan of `[from, to]` (inclusive) returning EVERY owned,
     * spendable output as JSON `[{block, amount, index, output}]` — the
     * wallet sums these (minus locally-known-spent) for the balance and
     * picks one to fund a send. `index` is the output's global on-chain
     * index, a stable id for spent-tracking. `on_block` reports progress.
     * @param {Uint8Array} spend_pub
     * @param {Uint8Array} view_key
     * @param {number} from
     * @param {number} to
     * @param {Function | null} [on_block]
     * @returns {Promise<string>}
     */
    scan_all(spend_pub, view_key, from, to, on_block) {
        const ptr0 = passArray8ToWasm0(spend_pub, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(view_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.xmrnode_scan_all(this.__wbg_ptr, ptr0, len0, ptr1, len1, from, to, isLikeNone(on_block) ? 0 : addToExternrefTable0(on_block));
        return ret;
    }
    /**
     * Build and sign a personal send spending ONE OR MORE outputs.
     *
     * `inputs_json` is `[{"output": "<hex>", "block": <n>}, ...]` from
     * [`Self::scan_all`]. Previously this took a single output, so a
     * wallet whose balance was split across several outputs could not
     * spend it at all — the caller had to find one output covering the
     * whole amount plus fee, or give up.
     *
     * Real decoys + live fee (sanity-capped); the builder errors if the
     * inputs cannot cover amount+fee (fail-closed). Returns JSON
     * `{tx, tx_hash, fee, inputs}` (hex); broadcast with [`Self::publish`].
     * @param {string} inputs_json
     * @param {Uint8Array} spend_secret
     * @param {string} dest
     * @param {string} amount_atomic
     * @param {string} change_address
     * @param {string} network
     * @returns {Promise<string>}
     */
    send(inputs_json, spend_secret, dest, amount_atomic, change_address, network) {
        const ptr0 = passStringToWasm0(inputs_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(spend_secret, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(dest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(amount_atomic, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(change_address, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.xmrnode_send(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        return ret;
    }
    /**
     * Build and sign the sweep of `output` (hex, from [`Self::scan`])
     * with the reconstructed joint spend secret: real decoys from the
     * daemon, live fee rate, CLSAG/Bulletproof+. Half the amount is an
     * explicit payment to `dest` and the remainder returns to `dest` as
     * change, so everything minus the fee lands at `dest` (the exact
     * shape of the on-chain-proven native sweep). Returns JSON
     * `{tx, tx_hash}` (hex); nothing is broadcast until [`Self::publish`].
     * @param {string} output_hex
     * @param {number} block
     * @param {Uint8Array} joint_secret
     * @param {string} dest
     * @param {string} network
     * @returns {Promise<string>}
     */
    sweep_sign(output_hex, block, joint_secret, dest, network) {
        const ptr0 = passStringToWasm0(output_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(joint_secret, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(dest, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.xmrnode_sweep_sign(this.__wbg_ptr, ptr0, len0, block, ptr1, len1, ptr2, len2, ptr3, len3);
        return ret;
    }
}
if (Symbol.dispose) XmrNode.prototype[Symbol.dispose] = XmrNode.prototype.free;
exports.XmrNode = XmrNode;

/**
 * @returns {boolean}
 */
function xmr_cosign_selftest() {
    const ret = wasm.xmr_cosign_selftest();
    return ret !== 0;
}
exports.xmr_cosign_selftest = xmr_cosign_selftest;

/**
 * Joint address derivation for JS. Returns JSON
 * `{address, spend_pub, view_key}` (hex where binary).
 * @param {Uint8Array} ctx
 * @param {Uint8Array} spend_pub_a
 * @param {Uint8Array} spend_pub_b
 * @param {Uint8Array} view_half_a
 * @param {Uint8Array} view_half_b
 * @param {string} network
 * @returns {string}
 */
function xmr_joint_info(ctx, spend_pub_a, spend_pub_b, view_half_a, view_half_b, network) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passArray8ToWasm0(ctx, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(spend_pub_a, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(spend_pub_b, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(view_half_a, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(view_half_b, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.xmr_joint_info(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}
exports.xmr_joint_info = xmr_joint_info;

/**
 * Joint spend-secret reconstruction for JS (32 bytes).
 * @param {Uint8Array} ctx
 * @param {Uint8Array} my_secret
 * @param {Uint8Array} their_secret
 * @returns {Uint8Array}
 */
function xmr_joint_secret(ctx, my_secret, their_secret) {
    const ptr0 = passArray8ToWasm0(ctx, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(my_secret, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(their_secret, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ret = wasm.xmr_joint_secret(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}
exports.xmr_joint_secret = xmr_joint_secret;

/**
 * Personal wallet identity for JS. Returns JSON `{address, spend_pub, view_key,
 * spend_secret}` (hex). `spend_secret` is the account's private key — the
 * caller (a Web Worker) must keep it confined and only surface it for backup.
 * @param {Uint8Array} seed
 * @param {string} network
 * @returns {string}
 */
function xmr_personal(seed, network) {
    let deferred4_0;
    let deferred4_1;
    try {
        const ptr0 = passArray8ToWasm0(seed, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(network, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.xmr_personal(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}
exports.xmr_personal = xmr_personal;

/**
 * secret·G, compressed — a party's Monero spend public key.
 * @param {Uint8Array} secret
 * @returns {Uint8Array}
 */
function xmr_spend_pub(secret) {
    const ptr0 = passArray8ToWasm0(secret, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.xmr_spend_pub(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}
exports.xmr_spend_pub = xmr_spend_pub;
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg___wbindgen_debug_string_a57024b9c6e4a48b: function(arg0, arg1) {
            const ret = debugString(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
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
        __wbg___wbindgen_string_get_d154f1e671052120: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_bb96b2010945f0bc: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg__wbg_cb_unref_be22cc64ae6946a0: function(arg0) {
            arg0._wbg_cb_unref();
        },
        __wbg_call_0f2a9af232c18fd2: function() { return handleError(function (arg0, arg1, arg2, arg3) {
            const ret = arg0.call(arg1, arg2, arg3);
            return ret;
        }, arguments); },
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
        __wbg_new_77cc4f4f472aeb81: function(arg0) {
            const ret = new Uint8Array(arg0);
            return ret;
        },
        __wbg_new_from_slice_3eea173078478cfe: function(arg0, arg1) {
            const ret = new Uint8Array(getArrayU8FromWasm0(arg0, arg1));
            return ret;
        },
        __wbg_new_typed_cceaf62d8d95e9f2: function(arg0, arg1) {
            try {
                var state0 = {a: arg0, b: arg1};
                var cb0 = (arg0, arg1) => {
                    const a = state0.a;
                    state0.a = 0;
                    try {
                        return wasm_bindgen__convert__closures_____invoke__h1d11c64ec0d5377c(a, state0.b, arg0, arg1);
                    } finally {
                        state0.a = a;
                    }
                };
                const ret = new Promise(cb0);
                return ret;
            } finally {
                state0.a = 0;
            }
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
        __wbg_queueMicrotask_ac694eae12e92dfb: function(arg0) {
            queueMicrotask(arg0);
        },
        __wbg_queueMicrotask_be5fe34a8f4cad4d: function(arg0) {
            const ret = arg0.queueMicrotask;
            return ret;
        },
        __wbg_randomFillSync_6c25eac9869eb53c: function() { return handleError(function (arg0, arg1) {
            arg0.randomFillSync(arg1);
        }, arguments); },
        __wbg_require_b4edbdcf3e2a1ef0: function() { return handleError(function () {
            const ret = module.require;
            return ret;
        }, arguments); },
        __wbg_resolve_020f95d838c6ef25: function(arg0) {
            const ret = Promise.resolve(arg0);
            return ret;
        },
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
        __wbg_then_7026b513a94278a8: function(arg0, arg1) {
            const ret = arg0.then(arg1);
            return ret;
        },
        __wbg_then_72819b8d4e081fb5: function(arg0, arg1, arg2) {
            const ret = arg0.then(arg1, arg2);
            return ret;
        },
        __wbg_versions_276b2795b1c6a219: function(arg0) {
            const ret = arg0.versions;
            return ret;
        },
        __wbg_xmrnode_new: function(arg0) {
            const ret = XmrNode.__wrap(arg0);
            return ret;
        },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Closure(Closure { owned: true, function: Function { arguments: [Externref], shim_idx: 321, ret: Result(Unit), inner_ret: Some(Result(Unit)) }, mutable: true }) -> Externref`.
            const ret = makeMutClosure(arg0, arg1, wasm_bindgen__convert__closures_____invoke__hc15e3e7919b5688a);
            return ret;
        },
        __wbindgen_cast_0000000000000002: function(arg0) {
            // Cast intrinsic for `F64 -> Externref`.
            const ret = arg0;
            return ret;
        },
        __wbindgen_cast_0000000000000003: function(arg0, arg1) {
            // Cast intrinsic for `Ref(Slice(U8)) -> NamedExternref("Uint8Array")`.
            const ret = getArrayU8FromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_cast_0000000000000004: function(arg0, arg1) {
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
        "./wasm_monero_bg.js": import0,
    };
}

function wasm_bindgen__convert__closures_____invoke__hc15e3e7919b5688a(arg0, arg1, arg2) {
    const ret = wasm.wasm_bindgen__convert__closures_____invoke__hc15e3e7919b5688a(arg0, arg1, arg2);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

function wasm_bindgen__convert__closures_____invoke__h1d11c64ec0d5377c(arg0, arg1, arg2, arg3) {
    wasm.wasm_bindgen__convert__closures_____invoke__h1d11c64ec0d5377c(arg0, arg1, arg2, arg3);
}

const XmrNodeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_xmrnode_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(state => wasm.__wbindgen_destroy_closure(state.a, state.b));

function debugString(val) {
    // primitive types
    const type = typeof val;
    if (type == 'number' || type == 'boolean' || val == null) {
        return  `${val}`;
    }
    if (type == 'string') {
        return `"${val}"`;
    }
    if (type == 'symbol') {
        const description = val.description;
        if (description == null) {
            return 'Symbol';
        } else {
            return `Symbol(${description})`;
        }
    }
    if (type == 'function') {
        const name = val.name;
        if (typeof name == 'string' && name.length > 0) {
            return `Function(${name})`;
        } else {
            return 'Function';
        }
    }
    // objects
    if (Array.isArray(val)) {
        const length = val.length;
        let debug = '[';
        if (length > 0) {
            debug += debugString(val[0]);
        }
        for(let i = 1; i < length; i++) {
            debug += ', ' + debugString(val[i]);
        }
        debug += ']';
        return debug;
    }
    // Test for built-in
    const builtInMatches = /\[object ([^\]]+)\]/.exec(toString.call(val));
    let className;
    if (builtInMatches && builtInMatches.length > 1) {
        className = builtInMatches[1];
    } else {
        // Failed to match the standard '[object ClassName]'
        return toString.call(val);
    }
    if (className == 'Object') {
        // we're a user defined class or Object
        // JSON.stringify avoids problems with cycles, and is generally much
        // easier than looping through ownProperties of `val`.
        try {
            return 'Object(' + JSON.stringify(val) + ')';
        } catch (_) {
            return 'Object';
        }
    }
    // errors
    if (val instanceof Error) {
        return `${val.name}: ${val.message}\n${val.stack}`;
    }
    // TODO we could test for more things here, like `Set`s and `Map`s.
    return className;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
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

function makeMutClosure(arg0, arg1, f) {
    const state = { a: arg0, b: arg1, cnt: 1 };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            state.a = a;
            real._wbg_cb_unref();
        }
    };
    real._wbg_cb_unref = () => {
        if (--state.cnt === 0) {
            wasm.__wbindgen_destroy_closure(state.a, state.b);
            state.a = 0;
            CLOSURE_DTORS.unregister(state);
        }
    };
    CLOSURE_DTORS.register(real, state, state);
    return real;
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
function decodeText(ptr, len) {
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

const wasmPath = `${__dirname}/wasm_monero_bg.wasm`;
const wasmBytes = require('fs').readFileSync(wasmPath);
const wasmModule = new WebAssembly.Module(wasmBytes);
let wasmInstance = new WebAssembly.Instance(wasmModule, __wbg_get_imports());
let wasm = wasmInstance.exports;
wasm.__wbindgen_start();
