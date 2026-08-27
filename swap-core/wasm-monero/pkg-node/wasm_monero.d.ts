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
     */
    send(inputs_json: string, spend_secret: Uint8Array, dest: string, amount_atomic: string, change_address: string, network: string): Promise<string>;
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
