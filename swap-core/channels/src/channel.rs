//! The one-way channel state machine.
//!
//! Invariants enforced on every accepted state (the I5 record, verified by
//! the executable model's S07/S09):
//! - Taker slice strictly increases (monotone; no reverse flow in a channel).
//! - Slices never exceed capacity; maker remainder is capacity − taker slice.
//! - Every state spends the same funding output (one key image for the whole
//!   channel — at most one state can ever confirm).
//! - The channel refuses new states past its lifetime cap, which the client
//!   sets strictly before the maker's puzzle horizon T2 (and before any
//!   announced fork height, N2).
//! - Chunks are credited only inside their own channel: a payment reference
//!   carries the channel id, and a mismatched id is refused outright
//!   (the S09 no-cross-channel-credit rule).

use monero_side::cosign::{cosign_in_process, verify_clsag, CosignError, StateSpend};
use monero_side::isolation::Bytes32;

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

/// Audit #4: the canonical signable hash binding a channel state to its
/// split. Both parties compute this deterministically; a state whose CLSAG
/// signs anything else is rejected, so a maker cannot pass a state that
/// pays itself everything while carrying a "correct" taker_amount field.
pub fn expected_state_msg(
    channel: &ChannelId,
    capacity: u64,
    taker_amount: u64,
    index: u64,
) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(b"XNOXMR-channel-state-v1");
    h.update(channel);
    h.update(capacity.to_be_bytes());
    h.update(taker_amount.to_be_bytes());
    h.update(index.to_be_bytes());
    h.finalize().into()
}

/// Identifies one channel; both parties derive it from the session
/// transcript (funding output key ‖ direction), so it cannot collide across
/// mirrored channels of the same pair.
pub type ChannelId = [u8; 32];

/// A completed, taker-held channel state: broadcastable as-is.
#[derive(Clone, Debug)]
pub struct SignedState {
    pub index: u64,
    /// Cumulative XMR owed to the taker after this state.
    pub taker_amount: u64,
    /// The signable-hash this state's CLSAG signs (the state tx hash).
    pub msg: [u8; 32],
    pub clsag: monero_clsag::Clsag,
    pub key_image: Bytes32,
    pub pseudo_out: Bytes32,
}

#[derive(Debug)]
pub enum ChannelError {
    /// New state does not strictly increase the taker slice.
    NotMonotone,
    /// Taker slice exceeds channel capacity.
    OverCapacity,
    /// The channel lifetime cap has passed; only closing is allowed.
    Expired,
    /// Payment reference names a different channel (cross-channel credit).
    WrongChannel,
    /// The state's signature or key image failed verification.
    InvalidState,
    /// Lifetime cap is not strictly before the puzzle horizon T2.
    BadLifetime,
    /// Underlying co-signing failure.
    Cosign(CosignError),
}

impl From<CosignError> for ChannelError {
    fn from(e: CosignError) -> Self {
        ChannelError::Cosign(e)
    }
}

/// A chunk-payment reference, as carried in the Nano chunk block metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub channel: ChannelId,
    pub new_taker_amount: u64,
}

/// The channel, as tracked identically by both parties. The taker
/// additionally holds `states`; the maker holds none of them.
pub struct Channel {
    pub id: ChannelId,
    /// Funding output capacity in XMR raw units.
    pub capacity: u64,
    /// Ring/opening material for the funding output — every state re-spends it.
    pub funding: FundingOutput,
    /// Client-enforced close deadline (e.g. seconds since epoch, or block
    /// height — any monotone clock both parties share).
    pub lifetime_cap: u64,
    /// The maker's puzzle horizon T2 on the same clock; the cap must sit
    /// strictly before it (I5 amendment: otherwise the backstop could claw
    /// back the taker's earned slice).
    pub horizon_t2: u64,
    /// Latest accepted taker slice.
    pub taker_amount: u64,
    /// Latest accepted state index.
    pub state_index: u64,
    /// The channel's single key image (set by the first state).
    pub key_image: Option<Bytes32>,
}

/// The funding output's spend material (shared by every state).
#[derive(Clone, Debug)]
pub struct FundingOutput {
    pub ring: Vec<[Bytes32; 2]>,
    pub ring_indices: Vec<u64>,
    pub real_index: usize,
    pub key_offset: Bytes32,
    pub mask: Bytes32,
}

impl Channel {
    /// Open a channel. Fails if the lifetime cap is not strictly before T2.
    pub fn open(
        id: ChannelId,
        capacity: u64,
        funding: FundingOutput,
        lifetime_cap: u64,
        horizon_t2: u64,
    ) -> Result<Self, ChannelError> {
        if lifetime_cap >= horizon_t2 {
            return Err(ChannelError::BadLifetime);
        }
        Ok(Self {
            id,
            capacity,
            funding,
            lifetime_cap,
            horizon_t2,
            taker_amount: 0,
            state_index: 0,
            key_image: None,
        })
    }

    /// Validate a chunk payment reference against this channel — the S09
    /// rule: value paid in another channel buys nothing here.
    pub fn accept_chunk_ref(&self, r: &ChunkRef, now: u64) -> Result<(), ChannelError> {
        if r.channel != self.id {
            return Err(ChannelError::WrongChannel);
        }
        if now >= self.lifetime_cap {
            return Err(ChannelError::Expired);
        }
        if r.new_taker_amount <= self.taker_amount {
            return Err(ChannelError::NotMonotone);
        }
        if r.new_taker_amount > self.capacity {
            return Err(ChannelError::OverCapacity);
        }
        Ok(())
    }

    /// Build the state spend for the next state (both parties derive the
    /// identical structure; `state_msg` is the state transaction's signable
    /// hash, which commits to the new split).
    pub fn state_spend(&self, state_msg: [u8; 32], pseudo_mask: Bytes32) -> StateSpend {
        StateSpend {
            ring: self.funding.ring.clone(),
            ring_indices: self.funding.ring_indices.clone(),
            real_index: self.funding.real_index,
            key_offset: self.funding.key_offset,
            mask: self.funding.mask,
            amount: self.capacity,
            pseudo_mask,
            msg: state_msg,
        }
    }

    /// Accept a fully co-signed state: verify it, enforce every invariant,
    /// advance the channel. (In the live protocol the taker runs this after
    /// the two-round ceremony; the in-process variant below drives both ends
    /// for tests and same-host use.)
    pub fn accept_state(
        &mut self,
        r: &ChunkRef,
        now: u64,
        state: SignedState,
    ) -> Result<SignedState, ChannelError> {
        self.accept_chunk_ref(r, now)?;
        if state.taker_amount != r.new_taker_amount {
            return Err(ChannelError::InvalidState);
        }
        // Audit #4: the signed message MUST be the canonical hash of this
        // exact split, so the CLSAG cannot secretly pay a different amount.
        let expected = expected_state_msg(
            &self.id,
            self.capacity,
            state.taker_amount,
            self.state_index + 1,
        );
        if state.msg != expected {
            return Err(ChannelError::InvalidState);
        }
        // The CLSAG must verify over the funding ring…
        if !verify_clsag(
            &state.clsag,
            &self.funding.ring,
            &state.key_image,
            &state.pseudo_out,
            &state.msg,
        ) {
            return Err(ChannelError::InvalidState);
        }
        // …and carry the channel's one key image (same funding output ⇒ same
        // image; a different image means a different — fake — input).
        match self.key_image {
            None => self.key_image = Some(state.key_image),
            Some(image) if image == state.key_image => {}
            Some(_) => return Err(ChannelError::InvalidState),
        }
        self.taker_amount = r.new_taker_amount;
        self.state_index += 1;
        Ok(state)
    }

    /// Co-sign and accept the next state in-process (both parties' keys on
    /// one host — the test/demo path; transport-split signing uses
    /// `monero_side::cosign::Cosigner` with the same `state_spend`).
    pub fn next_state_in_process(
        &mut self,
        r: &ChunkRef,
        now: u64,
        _state_msg: [u8; 32],
        pseudo_mask: Bytes32,
        keys: Vec<modular_frost::ThresholdKeys<modular_frost::curve::Ed25519>>,
    ) -> Result<SignedState, ChannelError> {
        self.accept_chunk_ref(r, now)?;
        // Audit #4: derive the canonical state msg from the split, don't trust
        // a caller-supplied one.
        let state_msg = expected_state_msg(
            &self.id,
            self.capacity,
            r.new_taker_amount,
            self.state_index + 1,
        );
        let spend = self.state_spend(state_msg, pseudo_mask);
        let (clsag, key_image, pseudo_out) = cosign_in_process(&spend, keys)?;
        let state = SignedState {
            index: self.state_index + 1,
            taker_amount: r.new_taker_amount,
            msg: state_msg,
            clsag,
            key_image,
            pseudo_out,
        };
        self.accept_state(r, now, state)
    }

    /// Maker's remainder under the latest state.
    pub fn maker_amount(&self) -> u64 {
        self.capacity - self.taker_amount
    }

    /// The fee-adjusted on-chain settlement outputs at channel close,
    /// `(taker_out, maker_out)`. The taker receives its full bought amount; the
    /// Monero network fee is deducted from the maker's change, since the maker
    /// funded the channel and bears the settlement cost. Together the two
    /// outputs sum to `capacity - fee`, which is exactly what the joint input
    /// can pay (see [`monero_side::fee::net_output_after_fee`]).
    ///
    /// Returns `None` if the maker's change cannot cover the fee — the channel
    /// is too drained to close by this policy, and the caller must either
    /// deduct from the taker's side or refuse to settle rather than sign a
    /// transaction whose outputs would not balance.
    pub fn settlement_split(&self, fee: u64) -> Option<(u64, u64)> {
        // The whole input (capacity) must still be covered: taker_out +
        // maker_out + fee == capacity, so guard the total against underflow.
        monero_side::fee::net_output_after_fee(self.capacity, fee)?;
        let maker_out = self.maker_amount().checked_sub(fee)?;
        Some((self.taker_amount, maker_out))
    }

    /// The settlement split priced at a live [`monero_side::fee::FeeRate`] and
    /// `priority` — the fee is estimated for the single-input, two-output sweep
    /// shape a channel close uses.
    pub fn settlement_split_at(
        &self,
        rate: &monero_side::fee::FeeRate,
        priority: monero_side::fee::Priority,
    ) -> Option<(u64, u64)> {
        self.settlement_split(monero_side::fee::sweep_fee(rate, priority))
    }

    /// Whether the client must force a close now (lifetime reached).
    pub fn must_close(&self, now: u64) -> bool {
        now >= self.lifetime_cap
    }
}
