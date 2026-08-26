//! Block 6 battery: a full channel session over real 2-of-2 CLSAG
//! co-signing — monotone states, one key image across the whole channel,
//! lifetime caps, cross-channel credit refusal (S09), and journal-based
//! stale-state conviction at recovery (S11).

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use rand::rngs::OsRng;
use rand::RngCore;

use channels::channel::{Channel, ChannelError, ChunkRef, FundingOutput};
use channels::journal::{anchor_block, judge_served_state, replay, ServeVerdict};
use monero_side::cosign::musig_threshold_keys;
use monero_side::isolation::{
    aggregate_spend, commitment, receiver_key_offset, sender_one_time_key, shared_view_key,
    Bytes32,
};
use nano_ceremony::block::{StateBlock, Subtype};

fn rand_scalar() -> Scalar {
    let mut wide = [0u8; 64];
    OsRng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn pubkey(s: &Scalar) -> Bytes32 {
    (s * ED25519_BASEPOINT_TABLE).compress().to_bytes()
}

struct Fixture {
    keys: Vec<modular_frost::ThresholdKeys<modular_frost::curve::Ed25519>>,
    funding: FundingOutput,
    capacity: u64,
}

/// A funded joint account with an 8-ring funding output of `capacity`.
fn fixture(capacity: u64) -> Fixture {
    let mut ctx = [0u8; 32];
    OsRng.fill_bytes(&mut ctx);
    let a = rand_scalar();
    let b = rand_scalar();
    let mut spend_pubs = vec![pubkey(&a), pubkey(&b)];
    spend_pubs.sort();
    let joint = aggregate_spend(ctx, &spend_pubs).unwrap();

    let mut va = [0u8; 32];
    let mut vb = [0u8; 32];
    OsRng.fill_bytes(&mut va);
    OsRng.fill_bytes(&mut vb);
    let view_key = shared_view_key(ctx, &va, &vb);
    let view_scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(view_key)).unwrap();
    let view_pub = pubkey(&view_scalar);

    let r = rand_scalar().to_bytes();
    let (tx_pub, output_key) = sender_one_time_key(&r, &view_pub, &joint, 0).unwrap();
    let key_offset = receiver_key_offset(&view_key, &tx_pub, &joint, 0, &output_key).unwrap();
    let mask = rand_scalar().to_bytes();
    let real_commitment = commitment(&mask, capacity).unwrap();

    let real_index = 3usize;
    let mut ring = Vec::new();
    for i in 0..8 {
        if i == real_index {
            ring.push([output_key, real_commitment]);
        } else {
            ring.push([
                pubkey(&rand_scalar()),
                commitment(&rand_scalar().to_bytes(), OsRng.next_u64()).unwrap(),
            ]);
        }
    }

    let ka = musig_threshold_keys(ctx, &a.to_bytes(), &spend_pubs).unwrap();
    let kb = musig_threshold_keys(ctx, &b.to_bytes(), &spend_pubs).unwrap();
    Fixture {
        keys: vec![ka, kb],
        funding: FundingOutput {
            ring,
            ring_indices: (1..=8).collect(),
            real_index,
            key_offset,
            mask,
        },
        capacity,
    }
}

fn msg32() -> [u8; 32] {
    let mut m = [0u8; 32];
    OsRng.fill_bytes(&mut m);
    m
}

#[test]
fn channel_session_monotone_states_one_key_image() {
    let f = fixture(1_000_000);
    let id = [7u8; 32];
    let mut ch = Channel::open(id, f.capacity, f.funding.clone(), 1_000, 2_000).unwrap();

    let mut images = Vec::new();
    let mut latest = None;
    for (i, amount) in [100_000u64, 250_000, 600_000].iter().enumerate() {
        let state = ch
            .next_state_in_process(
                &ChunkRef {
                    channel: id,
                    new_taker_amount: *amount,
                },
                10 + i as u64,
                msg32(),
                rand_scalar().to_bytes(),
                f.keys.clone(),
            )
            .expect("state accepted");
        images.push(state.key_image);
        latest = Some(state);
    }
    // One key image across the whole channel: only one state can ever confirm.
    assert!(images.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(ch.taker_amount, 600_000);
    assert_eq!(ch.maker_amount(), 400_000);
    assert_eq!(ch.state_index, 3);
    assert_eq!(latest.unwrap().index, 3);
}

#[test]
fn monotonicity_capacity_and_lifetime_are_enforced() {
    let f = fixture(500_000);
    let id = [9u8; 32];
    let mut ch = Channel::open(id, f.capacity, f.funding.clone(), 100, 200).unwrap();

    ch.next_state_in_process(
        &ChunkRef { channel: id, new_taker_amount: 200_000 },
        10,
        msg32(),
        rand_scalar().to_bytes(),
        f.keys.clone(),
    )
    .unwrap();

    // Equal or smaller slice: refused (no reverse flow inside a channel).
    assert!(matches!(
        ch.accept_chunk_ref(&ChunkRef { channel: id, new_taker_amount: 200_000 }, 11),
        Err(ChannelError::NotMonotone)
    ));
    assert!(matches!(
        ch.accept_chunk_ref(&ChunkRef { channel: id, new_taker_amount: 50_000 }, 11),
        Err(ChannelError::NotMonotone)
    ));
    // Over capacity: refused.
    assert!(matches!(
        ch.accept_chunk_ref(&ChunkRef { channel: id, new_taker_amount: 500_001 }, 11),
        Err(ChannelError::OverCapacity)
    ));
    // Past the lifetime cap: refused, and the client must close.
    assert!(matches!(
        ch.accept_chunk_ref(&ChunkRef { channel: id, new_taker_amount: 300_000 }, 100),
        Err(ChannelError::Expired)
    ));
    assert!(ch.must_close(100));
    // A cap at or past T2 cannot even open (I5 amendment).
    assert!(matches!(
        Channel::open([1u8; 32], 1, f.funding.clone(), 200, 200),
        Err(ChannelError::BadLifetime)
    ));
}

/// S09: mirrored channels settle independently; a chunk referencing channel A
/// buys nothing in channel B, ever.
#[test]
fn cross_channel_credit_is_refused() {
    let fa = fixture(300_000);
    let fb = fixture(300_000);
    let id_a = [0xAA; 32];
    let id_b = [0xBB; 32];
    let mut ch_a = Channel::open(id_a, fa.capacity, fa.funding.clone(), 1_000, 2_000).unwrap();
    let ch_b = Channel::open(id_b, fb.capacity, fb.funding.clone(), 1_000, 2_000).unwrap();

    let r_a = ChunkRef { channel: id_a, new_taker_amount: 100_000 };
    ch_a.next_state_in_process(&r_a, 10, msg32(), rand_scalar().to_bytes(), fa.keys.clone())
        .unwrap();

    // The same reference presented to channel B is refused outright.
    assert!(matches!(
        ch_b.accept_chunk_ref(&r_a, 10),
        Err(ChannelError::WrongChannel)
    ));
}

/// S11: the journal convicts a counterparty serving a stale state.
#[test]
fn journal_replay_convicts_stale_serve() {
    let account = [0x51; 32];
    let rep = [0x52; 32];
    let mut balance: u128 = 1_000;
    let mut prev = [0x50; 32];

    // Simulated journal account chain: an open marker, then three anchors.
    let mut chain = vec![StateBlock {
        account,
        previous: [0u8; 32],
        representative: rep,
        balance,
        link: [0xAA; 32],
        subtype: Subtype::Open,
    }];
    let states: Vec<[u8; 32]> = (0..3).map(|_| msg32()).collect();
    for s in &states {
        let b = anchor_block(account, prev, rep, balance, s).unwrap();
        balance -= 1;
        prev = b.hash();
        chain.push(b);
    }

    let anchors = replay(&chain);
    assert_eq!(anchors.len(), 3);
    assert_eq!(anchors, states.iter().map(|s| *s).collect::<Vec<_>>());

    // Serving the latest state: accepted.
    assert_eq!(judge_served_state(&anchors, &states[2]), ServeVerdict::Latest);
    // Serving an old state: convicted with positions as evidence.
    assert_eq!(
        judge_served_state(&anchors, &states[0]),
        ServeVerdict::Stale { served_pos: 0, tip_pos: 2 }
    );
    // Serving something never anchored: flagged.
    assert_eq!(judge_served_state(&anchors, &msg32()), ServeVerdict::Unanchored);
}

/// A forged state (wrong signature material) is rejected by accept_state.
#[test]
fn forged_state_is_rejected() {
    let f = fixture(400_000);
    let id = [3u8; 32];
    let mut ch = Channel::open(id, f.capacity, f.funding.clone(), 1_000, 2_000).unwrap();

    let good = ch
        .next_state_in_process(
            &ChunkRef { channel: id, new_taker_amount: 100_000 },
            10,
            msg32(),
            rand_scalar().to_bytes(),
            f.keys.clone(),
        )
        .unwrap();

    // Replay the same CLSAG with a different message: fails verification.
    let mut forged = good.clone();
    forged.msg = msg32();
    forged.taker_amount = 200_000;
    assert!(matches!(
        ch.accept_state(
            &ChunkRef { channel: id, new_taker_amount: 200_000 },
            11,
            forged
        ),
        Err(ChannelError::InvalidState)
    ));
}

/// Audit (channel-journal break): judge_served_indexed looks the served hash
/// up in the TRUSTED anchor log by hash and uses that anchor's own index — it
/// no longer trusts a counterparty-supplied index, so a stale-but-anchored
/// serve can't be relabeled Unanchored/Latest to dodge conviction.
#[test]
fn indexed_judge_convicts_stale_regardless_of_forged_anchor() {
    use channels::journal::judge_served_indexed;
    let h0 = msg32();
    let h1 = msg32();
    let h2 = msg32();
    let anchors = vec![(0u64, h0), (1, h1), (2, h2)];

    // Serving the tip: Latest. Serving an old state: convicted Stale.
    assert_eq!(judge_served_indexed(&anchors, &h2), ServeVerdict::Latest);
    assert_eq!(
        judge_served_indexed(&anchors, &h0),
        ServeVerdict::Stale { served_pos: 0, tip_pos: 2 }
    );
    // A never-anchored hash is Unanchored.
    assert_eq!(judge_served_indexed(&anchors, &msg32()), ServeVerdict::Unanchored);

    // Even if a forged duplicate anchor binds the old hash at the tip index,
    // the hash's FIRST (real) anchor wins → still convicted Stale.
    let tampered = vec![(0u64, h0), (1, h1), (2, h2), (2, h0)];
    assert_eq!(
        judge_served_indexed(&tampered, &h0),
        ServeVerdict::Stale { served_pos: 0, tip_pos: 2 }
    );
}

/// The on-chain close deducts the Monero fee from the maker's change; the two
/// outputs sum to capacity - fee, and a channel too drained to cover the fee
/// refuses to produce a split rather than sign an unbalanced transaction.
#[test]
fn settlement_split_deducts_fee_and_guards_underflow() {
    let f = fixture(1_000_000);
    let id = [0x5e; 32];
    let mut ch = Channel::open(id, f.capacity, f.funding.clone(), 1_000, 2_000).unwrap();
    ch.next_state_in_process(
        &ChunkRef { channel: id, new_taker_amount: 600_000 },
        10, msg32(), rand_scalar().to_bytes(), f.keys.clone(),
    ).unwrap();

    // Maker change is 400_000; a 10_000 fee leaves 390_000. Taker keeps 600_000.
    let (taker_out, maker_out) = ch.settlement_split(10_000).unwrap();
    assert_eq!(taker_out, 600_000);
    assert_eq!(maker_out, 390_000);
    assert_eq!(taker_out + maker_out + 10_000, ch.capacity);

    // A fee exceeding the maker's change refuses to split.
    assert!(ch.settlement_split(400_001).is_none());

    // Live-rate variant produces a balanced split. (FeeRate::FALLBACK is in
    // real piconero and would dwarf this toy capacity, so use a small explicit
    // rate here — the arithmetic path is identical.)
    use monero_side::fee::{FeeRate, Priority};
    let rate = FeeRate { per_weight: [1, 2, 3, 4], quantization_mask: 100 };
    let (t, m) = ch.settlement_split_at(&rate, Priority::Normal).unwrap();
    assert_eq!(t, 600_000);
    assert!(t + m < ch.capacity && t + m > 590_000); // small fee deducted
}
