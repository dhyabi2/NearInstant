/* tslint:disable */
/* eslint-disable */

/**
 * A connected Monero daemon, everything routed through the JS fetch.
 */
export class XmrNode {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Connect (probes the daemon once). `post_fn(route, body) -> Promise<Uint8Array>`.
     */
    static connect(post_fn: Function): Promise<XmrNode>;
    /**
     * Current chain height (the number of the next block).
     */
    height(): Promise<number>;
    /**
     * Broadcast a signed transaction (hex). Returns its hash.
     */
    publish(tx_hex: string): Promise<string>;
    /**
     * View-key scan of blocks `[from, to]` (inclusive, descending) for
     * outputs paid to the joint address. Returns JSON
     * `{block, amount, output}` (output = hex WalletOutput, spendable
     * input to `sweep_sign`) for the first hit, or `null`. `on_block`,
     * if given, is called with each block number scanned.
     */
    scan(spend_pub: Uint8Array, view_key: Uint8Array, from: number, to: number, on_block?: Function | null): Promise<any>;
    /**
     * View-key scan of `[from, to]` (inclusive) returning EVERY owned,
     * spendable output as JSON `[{block, amount, index, output}]` — the
     * wallet sums these (minus locally-known-spent) for the balance and
     * picks one to fund a send. `index` is the output's global on-chain
     * index, a stable id for spent-tracking. `on_block` reports progress.
     */
    scan_all(spend_pub: Uint8Array, view_key: Uint8Array, from: number, to: number, on_block?: Function | null): Promise<string>;
    /**
     * Build and sign a personal send: spend `output` (hex, from
     * [`Self::scan_all`]) with the wallet's `spend_secret`, paying
     * `amount_atomic` piconero to `dest` and returning the change to
     * `change_address` (the wallet's own address). Real decoys + live fee;
     * the builder errors if the input can't cover amount+fee (fail-closed).
     * Returns JSON `{tx, tx_hash}` (hex); broadcast with [`Self::publish`].
     */
    send(output_hex: string, block: number, spend_secret: Uint8Array, dest: string, amount_atomic: string, change_address: string, network: string): Promise<string>;
    /**
     * Build and sign the sweep of `output` (hex, from [`Self::scan`])
     * with the reconstructed joint spend secret: real decoys from the
     * daemon, live fee rate, CLSAG/Bulletproof+. Half the amount is an
     * explicit payment to `dest` and the remainder returns to `dest` as
     * change, so everything minus the fee lands at `dest` (the exact
     * shape of the on-chain-proven native sweep). Returns JSON
     * `{tx, tx_hash}` (hex); nothing is broadcast until [`Self::publish`].
     */
    sweep_sign(output_hex: string, block: number, joint_secret: Uint8Array, dest: string, network: string): Promise<string>;
}

/**
 * Self-test the 2-of-2 CLSAG co-signing (I5) in the browser: run the whole
 * multisig ceremony in-process over a synthetic joint output and verify the
 * resulting CLSAG. This is the exact primitive a real two-party Monero *refund*
 * needs (neither party can sign a spend of the joint lock output alone). Proves
 * it compiles and runs in wasm without a counterparty or network.
 */
export function xmr_cosign_selftest(): boolean;

/**
 * Joint address derivation for JS. Returns JSON
 * `{address, spend_pub, view_key}` (hex where binary).
 */
export function xmr_joint_info(ctx: Uint8Array, spend_pub_a: Uint8Array, spend_pub_b: Uint8Array, view_half_a: Uint8Array, view_half_b: Uint8Array, network: string): string;

/**
 * Joint spend-secret reconstruction for JS (32 bytes).
 */
export function xmr_joint_secret(ctx: Uint8Array, my_secret: Uint8Array, their_secret: Uint8Array): Uint8Array;

/**
 * Personal wallet identity for JS. Returns JSON `{address, spend_pub, view_key,
 * spend_secret}` (hex). `spend_secret` is the account's private key — the
 * caller (a Web Worker) must keep it confined and only surface it for backup.
 */
export function xmr_personal(seed: Uint8Array, network: string): string;

/**
 * secret·G, compressed — a party's Monero spend public key.
 */
export function xmr_spend_pub(secret: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly xmr_cosign_selftest: () => number;
    readonly xmr_joint_info: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly xmr_joint_secret: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly xmr_personal: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly xmr_spend_pub: (a: number, b: number) => [number, number, number, number];
    readonly __wbg_xmrnode_free: (a: number, b: number) => void;
    readonly xmrnode_connect: (a: any) => any;
    readonly xmrnode_height: (a: number) => any;
    readonly xmrnode_publish: (a: number, b: number, c: number) => any;
    readonly xmrnode_scan: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly xmrnode_scan_all: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
    readonly xmrnode_send: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number) => any;
    readonly xmrnode_sweep_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => any;
    readonly wasm_bindgen__convert__closures_____invoke__hc15e3e7919b5688a: (a: number, b: number, c: any) => [number, number];
    readonly wasm_bindgen__convert__closures_____invoke__h1d11c64ec0d5377c: (a: number, b: number, c: any, d: any) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_destroy_closure: (a: number, b: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
