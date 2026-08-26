/* tslint:disable */
/* eslint-disable */

export class BrowserDkg {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The joint account once the DKG has finished (hex `nano_…` account is
     * derivable from these 32 bytes).
     */
    account(): Uint8Array | undefined;
    /**
     * This party's serialized key package (its OWN secret share) — feed it,
     * with `public_key_package`, into a `BrowserSigner` to sign or adaptor-
     * pre-sign. Available only after the DKG has finished.
     */
    key_package(): Uint8Array | undefined;
    /**
     * Begin the DKG (runs part1). `my_id`/`their_id` are the two party ids
     * (1 and 2, opposite on each side).
     */
    constructor(my_id: number, their_id: number);
    /**
     * Deterministic DKG for reproducible per-session joint accounts: identical
     * to `new` but seeds part1's randomness from a 32-byte session seed
     * (derive it from your wallet seed + a unique session id). part2/part3 are
     * already pure, so the whole DKG — and thus the joint account — is a
     * deterministic function of the two seeds. SAFE: this fixes the long-term
     * KEY SHARES (like an HD wallet), never the per-signature nonces, which
     * stay fresh (see `sign_commit`). Reuse a seed only with a unique session
     * id so every swap gets its own account.
     */
    static newSeeded(my_id: number, their_id: number, seed: Uint8Array): BrowserDkg;
    /**
     * The shared public key package (same on both parties). Feed it into a
     * `BrowserSigner`. Available only after the DKG has finished.
     */
    public_key_package(): Uint8Array | undefined;
    /**
     * Our round-1 package to send to the peer.
     */
    round1_out(): Uint8Array;
    /**
     * Our round-2 package to send to the peer.
     */
    round2_out(): Uint8Array;
    /**
     * Feed the peer's round-1 package; runs part2 and prepares our round-2
     * package (fetch it with `round2_out`).
     */
    set_peer_round1(bytes: Uint8Array): void;
    /**
     * Feed the peer's round-2 package; runs part3 and returns the 32-byte
     * joint Nano account both parties share.
     */
    set_peer_round2(bytes: Uint8Array): Uint8Array;
}

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
    free(): void;
    [Symbol.dispose](): void;
    /**
     * The 32-byte joint Nano account (verifying key).
     */
    account(): Uint8Array;
    /**
     * Aggregate the adaptor shares into a 96-byte pre-signature
     * (`r_adapted ‖ s_hat ‖ adaptor_point`).
     */
    aggregate_presig(): Uint8Array;
    /**
     * Aggregate the plain shares into the 64-byte Nano-valid joint signature.
     */
    aggregate_sig(): Uint8Array;
    /**
     * Build a signer from a finished DKG's serialized key material.
     */
    constructor(key_package: Uint8Array, public_key_package: Uint8Array, _my_id: number, their_id: number);
    /**
     * Begin an adaptor pre-signing round on `message` for `adaptor_point`
     * (`T = x·G`, 32 bytes).
     */
    presign_commit(message: Uint8Array, adaptor_point: Uint8Array): Uint8Array;
    /**
     * Produce our adaptor signature share (also kept for aggregation).
     *
     * CONSUMES the round's nonces (`take()`) for the same reason as
     * `sign_share`: single-use per nonce pair, or the secret share leaks.
     */
    presign_share(): Uint8Array;
    /**
     * Feed the peer's commitment (from either commit step).
     */
    set_peer_commit(bytes: Uint8Array): void;
    /**
     * Feed the peer's signature share (plain or adaptor).
     */
    set_peer_share(bytes: Uint8Array): void;
    /**
     * Begin a plain signing round on `message` (a 32-byte block hash).
     */
    sign_commit(message: Uint8Array): Uint8Array;
    /**
     * Produce our plain signature share (also kept for aggregation).
     *
     * CONSUMES the round's nonces (`take()`): a FROST signing nonce pair must
     * sign exactly ONE message. Producing a second share from the same nonces
     * against a different peer commitment yields a solvable linear system that
     * recovers our long-term secret share, so a second call here fails closed
     * ("call sign_commit first") rather than reusing the nonce.
     */
    sign_share(): Uint8Array;
}

/**
 * Argon2id as a raw 32-byte key-derivation function (NOT reduced to a curve
 * scalar): the wallet uses this to derive an AES-256-GCM key that encrypts the
 * random wallet seed at rest. Same memory-hard parameters as `argon2id_seed`
 * (OWASP floor 19 MiB, t=2, p=1; `mem_kib` may raise it). `salt` ≥ 8 bytes.
 * Returns the full 32-byte tag, or an empty vec on bad input.
 */
export function argon2id_raw(passphrase: string, salt: Uint8Array, mem_kib: number): Uint8Array;

/**
 * Stage 6 custody: stretch a human passphrase into a 32-byte wallet seed with
 * Argon2id (memory-hard — a stolen page or shoulder-surfed passphrase still
 * costs the attacker the full KDF per guess). Runs inside a Web Worker whose
 * scope the DOM cannot read, so the seed never touches the page. `salt` must
 * be ≥ 8 bytes and STABLE for an account (store it, e.g. localStorage). Params
 * are the OWASP-recommended Argon2id floor (19 MiB, t=2, p=1); `mem_kib` may
 * raise the memory cost. Returns the 32-byte seed (feed to `seed_account` /
 * `sign_state_block`), or an empty vec on bad input.
 */
export function argon2id_seed(passphrase: string, salt: Uint8Array, mem_kib: number): Uint8Array;

/**
 * Run one real atomic chunk (Nano leg) and return a JSON string of every
 * artifact. Takes ~a few ms of curve math plus demo PoW.
 */
export function atomic_chunk_demo(chunk_raw: bigint): string;

/**
 * The deterministic burn account (32 bytes) for a market side.
 * `side`: 0 = sell XNO, 1 = sell XMR. Mirrors `dex_core::beacon::namespace_account`.
 */
export function beacon_account(pair: string, side: number): Uint8Array;

/**
 * The namespace account as a `nano_…` address (what the receivable RPC takes).
 */
export function beacon_address(pair: string, side: number): string;

/**
 * Decode a receivable raw amount (decimal string) back into an intent as
 * JSON `{"side":n,"price_e9":n,"size_log2":n}`, or empty string for anything
 * that is not beacon-encoded (junk dust, bad checksum, wrong version).
 */
export function beacon_decode(amount_raw: string): string;

/**
 * Encode an order intent into the raw dust amount (decimal string, < 2^64).
 * Empty string if `price_e9` overflows its 40-bit field.
 */
export function beacon_encode(side: number, price_e9: bigint, size_log2: number): string;

/**
 * Version tag for the UI.
 */
export function engine_version(): string;

export function escrow_selftest(): string;

/**
 * Generate a fresh adaptor secret `x` and its point `T = x·G` (32 ‖ 32 bytes).
 * In a real swap the XMR-seller does this: `T` becomes the adaptor point (its
 * Monero spend key), and revealing `x` by completing the Nano claim is what
 * hands the sweep secret to the counterparty. Exposed so the browser side that
 * owns the Monero key can produce the pair.
 */
export function gen_adaptor(): Uint8Array;

/**
 * A persistent browser identity: a fresh ed25519 key pair returned as
 * `{"seed": <hex32>, "pubkey": <hex32>}`. The caller stores the seed (e.g. in
 * localStorage) and passes it to `make_order_seeded` / `make_pof` so the maker
 * keeps ONE identity across orders instead of a throwaway key per order.
 */
export function gen_identity(): string;

/**
 * Sign a specific order (side 0=sell XNO, 1=sell XMR) with the given amount
 * in milli-XNO and rate in micro (XMR-per-XNO × 1e6). `now_secs` is the JS
 * wall clock (seconds); the order expires `now_secs + ORDER_TTL_SECS`.
 * Returns hex wire bytes, or an empty string if the amount would overflow.
 * Same canonical encoding as dex_core::order.
 */
export function make_order(side: number, amount_milli_xno: bigint, rate_micro: bigint, nonce: bigint, now_secs: bigint): string;

/**
 * Sign an order with the identity seed and an explicit `pof_hash` (from
 * `make_pof`), so the order carries a REAL proof-of-funds commitment instead
 * of the `NO_POF` sentinel. `side` 0 = sell XNO, 1 = sell XMR; `amount_milli_xno`
 * is milli-XNO; `rate_micro` is XMR-per-XNO × 1e6. Returns hex wire bytes.
 */
export function make_order_seeded(seed_hex: string, side: number, amount_milli_xno: bigint, rate_micro: bigint, nonce: bigint, now_secs: bigint, pof_hash_hex: string): string;

/**
 * Sign a Nano proof-of-funds with the identity seed: a statement that the
 * account controls at least `amount_raw` (decimal string, raw units). Returns
 * `{"hash": <hex32>, "wire": <hex>}` — `hash` is the value to put in the
 * order's `pof_hash` field; `wire` is the signed proof (gossiped beside the
 * order via the peer `0x02` frame). Format matches `dex_core::pof::NanoFundsProof`.
 */
export function make_pof(seed_hex: string, amount_raw: string, as_of_block: bigint, expires: bigint, nonce: bigint): string;

/**
 * Produce a real signed order (ed25519-blake2b) as hex wire bytes, for the
 * browser to gossip to the live relay. Inlines the dex-core order wire
 * format so the wasm stays light (signing crate only, no Monero deps).
 */
export function make_test_order(now_secs: bigint): string;

/**
 * Decode a `nano_…`/`xrb_…` address to its 32-byte public key (empty on error).
 */
export function nano_address_decode(addr: string): Uint8Array;

/**
 * Encode a 32-byte public key as a `nano_…` address (empty on bad length).
 */
export function nano_address_encode(public_key: Uint8Array): string;

/**
 * Verify a completed 64-byte signature as a real Nano signature for
 * `account` over `message`.
 */
export function nano_check(account: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;

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
 */
export function pledge_selftest(): boolean;

/**
 * Complete a 96-byte pre-signature with the 32-byte adaptor secret `x`,
 * yielding the 64-byte Nano wire signature. Broadcasting it reveals `x`.
 */
export function presig_complete(presig: Uint8Array, secret: Uint8Array): Uint8Array;

/**
 * Extract the adaptor secret `x` from a broadcast signature and the
 * pre-signature it completed (`x = s − ŝ`). This is how the XNO-seller learns
 * the Monero sweep secret the instant the claim is published.
 */
export function presig_extract(presig: Uint8Array, signature: Uint8Array): Uint8Array;

/**
 * Verify the adaptor relation of a pre-signature against the joint `account`
 * and 32-byte message — provable from public data alone.
 */
export function presig_verify(presig: Uint8Array, account: Uint8Array, message: Uint8Array): boolean;

/**
 * The identity seed's public half as JSON `{"pubkey":hex,"address":"nano_…"}`
 * — a browser identity IS a Nano account; fund it to publish beacons.
 */
export function seed_account(seed_hex: string): string;

/**
 * Build and sign a Nano state block with the identity seed (single-key
 * account — used for beacon publishes and pocketing dust; joint 2-of-2 blocks
 * go through `BrowserSigner`). Inputs are hex/decimal strings; `subtype` is
 * one of open|receive|send|change. Returns the full `process` RPC body as
 * JSON (work left as the placeholder `"WORK"` for the caller to fill) plus
 * `hash` and `work_root`, or empty string on bad input.
 */
export function sign_state_block(seed_hex: string, previous_hex: string, representative_hex: string, balance_raw: string, link_hex: string, subtype: string): string;

/**
 * The canonical 32-byte hash of a Nano state block, without signing it. The
 * swap driver needs this to bind the adaptor pre-signature to the REAL claim
 * block both parties agree on (the send that pays the XMR-seller their XNO),
 * rather than an arbitrary message. Same field encoding as `sign_state_block`.
 */
export function state_block_hash(account_hex: string, previous_hex: string, representative_hex: string, balance_raw: string, link_hex: string, subtype: string): Uint8Array;

/**
 * Validate a work nonce against a threshold (mirror of the node's check).
 */
export function work_check(root: Uint8Array, nonce: bigint, threshold: bigint): boolean;

/**
 * Search `count` nonces from `start` for work over `root` meeting `threshold`.
 * Returns the nonce or `undefined` — the browser calls this in chunks from an
 * async loop (or a Worker) so the UI stays alive; the found nonce is verified
 * by any Nano node exactly like node-generated work.
 */
export function work_search(root: Uint8Array, threshold: bigint, start: bigint, count: bigint): bigint | undefined;

/**
 * Nano mainnet work thresholds, as hex strings the JS side can hold as BigInt.
 */
export function work_thresholds(): string;
