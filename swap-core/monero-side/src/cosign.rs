//! 2-of-2 CLSAG co-signing of channel state transactions (I5).
//!
//! The joint spend key is a MuSig aggregation of the two parties' spend
//! contributions ([`crate::isolation::aggregate_spend`]); each party turns
//! their contribution into `ThresholdKeys` here. Spending a concrete output
//! offsets those keys by the output's key offset (from
//! [`crate::isolation::receiver_key_offset`]) and runs `monero-clsag`'s
//! multisig FROST algorithm, yielding the CLSAG and the joint key image —
//! which neither party could compute alone.

use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::group::ff::PrimeField;
use ciphersuite::group::GroupEncoding;
use modular_frost::sign::Writable as _;
use dalek_ff_group as dfg;
use modular_frost::{
    curve::Ed25519,
    dkg::Interpolation,
    sign::{AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine, PreprocessMachine, SignMachine, SignatureMachine},
    Participant, ThresholdKeys,
};
use monero_clsag::{Clsag, ClsagContext, ClsagMultisig, Decoys};
use monero_wallet::ed25519::{Commitment, CompressedPoint, Point, Scalar as MScalar};
use rand_core::OsRng;
use transcript_lib::RecommendedTranscript;

use crate::isolation::Bytes32;

// `flexible-transcript` exposes itself as `transcript`.
use ::transcript as transcript_lib;
use transcript_lib::Transcript as _;

/// Errors from the co-signing module.
#[derive(Debug)]
pub enum CosignError {
    /// A key or point failed validation.
    InvalidKey,
    /// The ring is malformed (bad member, bad index, wrong opening).
    InvalidRing,
    /// The FROST ceremony failed (bad preprocess/share from a party).
    Ceremony(String),
}

/// Build this party's `ThresholdKeys` for the 2-of-2 joint spend key via
/// MuSig aggregation. Both parties must pass the identical `context` and the
/// identically-ordered `spend_pubs` list containing both contributions.
pub fn musig_threshold_keys(
    context: Bytes32,
    my_spend_secret: &Bytes32,
    spend_pubs: &[Bytes32],
) -> Result<ThresholdKeys<Ed25519>, CosignError> {
    let secret = Option::<dfg::Scalar>::from(dfg::Scalar::from_repr(*my_spend_secret))
        .ok_or(CosignError::InvalidKey)?;
    let mut keys = Vec::with_capacity(spend_pubs.len());
    for pk in spend_pubs {
        let p = Option::<dfg::EdwardsPoint>::from(dfg::EdwardsPoint::from_bytes(pk))
            .ok_or(CosignError::InvalidKey)?;
        keys.push(p);
    }
    dkg_musig::musig::<Ed25519>(context, Zeroizing::new(secret), &keys)
        .map_err(|e| CosignError::Ceremony(format!("{e:?}")))
}

/// Reconstruct the joint XMR spend SECRET from this party's secret and the
/// counterparty's revealed secret, via the MuSig binding constants — the value
/// Alice computes once the Nano claim reveals `x` (Bob's XMR secret):
/// `Σ binding_i · secret_i`, which opens [`crate::isolation::aggregate_spend`].
/// Neither party can compute it alone; this is the hinge of the atomic swap's
/// Monero leg.
pub fn reconstruct_joint_secret(
    context: Bytes32,
    my_secret: &Bytes32,
    their_secret: &Bytes32,
    spend_pubs: &[Bytes32],
) -> Result<Bytes32, CosignError> {
    let my_keys = musig_threshold_keys(context, my_secret, spend_pubs)?;
    let Interpolation::Constant(bindings) = my_keys.interpolation().clone() else {
        return Err(CosignError::Ceremony("expected MuSig constant interpolation".into()));
    };
    let my_pub = (&scalar(my_secret)? * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let their_pub = (&scalar(their_secret)? * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let idx = |pk: &Bytes32| spend_pubs.iter().position(|p| p == pk);
    let my_idx = idx(&my_pub).ok_or(CosignError::InvalidKey)?;
    let their_idx = idx(&their_pub).ok_or(CosignError::InvalidKey)?;
    let joint = bindings[my_idx] * scalar(my_secret)? + bindings[their_idx] * scalar(their_secret)?;
    Ok(joint.to_bytes())
}

/// Everything needed to co-sign one CLSAG input of a state transaction.
pub struct StateSpend {
    /// The ring: `[output key, commitment]` pairs (compressed).
    pub ring: Vec<[Bytes32; 2]>,
    /// Global output indices for the ring members (as the tx will reference them).
    pub ring_indices: Vec<u64>,
    /// Position of the real spent output in the ring.
    pub real_index: usize,
    /// The real output's key offset (`isolation::receiver_key_offset`).
    pub key_offset: Bytes32,
    /// The real output's commitment opening.
    pub mask: Bytes32,
    pub amount: u64,
    /// The pseudo-out mask for this input (chosen by the transaction builder
    /// so pseudo-outs sum to the output commitments).
    pub pseudo_mask: Bytes32,
    /// The transaction signable hash this CLSAG signs.
    pub msg: [u8; 32],
}

fn scalar(bytes: &Bytes32) -> Result<curve25519_dalek::Scalar, CosignError> {
    Option::from(curve25519_dalek::Scalar::from_canonical_bytes(*bytes))
        .ok_or(CosignError::InvalidKey)
}

impl StateSpend {
    fn context(&self) -> Result<ClsagContext, CosignError> {
        let mut ring = Vec::with_capacity(self.ring.len());
        for [key, commitment] in &self.ring {
            let k = CompressedPoint::from(*key)
                .decompress()
                .ok_or(CosignError::InvalidRing)?;
            let c = CompressedPoint::from(*commitment)
                .decompress()
                .ok_or(CosignError::InvalidRing)?;
            ring.push([k, c]);
        }
        let decoys = Decoys::new(
            self.ring_indices.clone(),
            u8::try_from(self.real_index).map_err(|_| CosignError::InvalidRing)?,
            ring,
        )
        .ok_or(CosignError::InvalidRing)?;
        ClsagContext::new(
            decoys,
            Commitment::new(MScalar::from(scalar(&self.mask)?), self.amount),
        )
        .map_err(|_| CosignError::InvalidRing)
    }

    fn algorithm(&self) -> Result<ClsagMultisig, CosignError> {
        let (algorithm, mask_send) = ClsagMultisig::new(
            RecommendedTranscript::new(b"XNOXMR channel state CLSAG"),
            self.context()?,
        );
        mask_send.send(scalar(&self.pseudo_mask)?);
        Ok(algorithm)
    }

    /// The pseudo-out commitment this input will carry.
    pub fn pseudo_out(&self) -> Option<Bytes32> {
        crate::isolation::commitment(&self.pseudo_mask, self.amount)
    }
}

/// One party's signing machine, stepped through the two FROST rounds.
/// Transport of the serialized preprocess/share between parties is the
/// caller's job (Block 4+); [`cosign_in_process`] drives both ends locally.
pub struct Cosigner {
    machine: Option<AlgorithmMachine<Ed25519, ClsagMultisig>>,
    sign: Option<AlgorithmSignMachine<Ed25519, ClsagMultisig>>,
    complete: Option<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
    key_image_share: Bytes32,
    /// Audit #2: the one-way channel is safe only if the MAKER never obtains a
    /// broadcastable state (`finish`). A maker Cosigner is constructed with
    /// `may_complete = false`; only the taker completes. `finish` refuses when
    /// this is false, so a maker that (via a naive symmetric transport)
    /// receives the taker's share still cannot assemble a CLSAG to hoard and
    /// later broadcast the state most favorable to itself.
    may_complete: bool,
}

impl Cosigner {
    /// Create a cosigner for a state spend. `keys` are the MuSig threshold
    /// keys offset by the output's key offset.
    pub fn new(spend: &StateSpend, keys: ThresholdKeys<Ed25519>) -> Result<Self, CosignError> {
        // Defaults to the completing (taker) role; `with_role` validates the
        // key offset. Maker-side callers must use `with_role(.., false)`.
        Self::with_role(spend, keys, true)
    }

    /// Construct with an explicit completion role. Pass `may_complete = false`
    /// for the MAKER side (audit #2): it participates in signing so the taker
    /// can complete, but can never itself produce a broadcastable CLSAG.
    pub fn with_role(
        spend: &StateSpend,
        keys: ThresholdKeys<Ed25519>,
        may_complete: bool,
    ) -> Result<Self, CosignError> {
        let offset = Option::<dfg::Scalar>::from(dfg::Scalar::from_repr(spend.key_offset))
            .ok_or(CosignError::InvalidKey)?;
        let key_image_share = interpolated_image_share(&keys, &spend.ring[spend.real_index][0])?;
        let keys = keys.offset(offset);
        Ok(Self {
            machine: Some(AlgorithmMachine::new(spend.algorithm()?, keys)),
            sign: None,
            complete: None,
            key_image_share,
            may_complete,
        })
    }

    /// This party's interpolated key-image share, `b_i·x_i·Hp(P)` — published
    /// to the counterparty so both can assemble the joint key image.
    pub fn key_image_share(&self) -> Bytes32 {
        self.key_image_share
    }

    /// Round 1: produce this party's preprocess (send to the counterparty).
    pub fn preprocess(&mut self) -> Result<Vec<u8>, CosignError> {
        let machine = self
            .machine
            .take()
            .ok_or_else(|| CosignError::Ceremony("preprocess called twice".into()))?;
        let (sign, preprocess) = machine.preprocess(&mut OsRng);
        self.sign = Some(sign);
        let mut out = Vec::new();
        preprocess
            .write(&mut out)
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        Ok(out)
    }

    /// Round 2: consume the counterparty's preprocess, produce our share.
    pub fn share(
        &mut self,
        counterparty: Participant,
        counterparty_preprocess: &[u8],
        msg: &[u8; 32],
    ) -> Result<Vec<u8>, CosignError> {
        let sign = self
            .sign
            .take()
            .ok_or_else(|| CosignError::Ceremony("share before preprocess".into()))?;
        let their_preprocess = sign
            .read_preprocess(&mut &counterparty_preprocess[..])
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        let mut map = HashMap::new();
        map.insert(counterparty, their_preprocess);
        let (complete, share) = sign
            .sign(map, msg)
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        self.complete = Some(complete);
        let mut out = Vec::new();
        share
            .write(&mut out)
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        Ok(out)
    }

    /// Finish: consume the counterparty's share, produce the CLSAG and the
    /// joint key image.
    pub fn finish(
        self,
        counterparty: Participant,
        counterparty_share: &[u8],
    ) -> Result<(Clsag, Bytes32), CosignError> {
        if !self.may_complete {
            return Err(CosignError::Ceremony(
                "maker role must not complete a channel state (audit #2)".into(),
            ));
        }
        let complete = self
            .complete
            .ok_or_else(|| CosignError::Ceremony("finish before share".into()))?;
        let their_share = complete
            .read_share(&mut &counterparty_share[..])
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        let mut map = HashMap::new();
        map.insert(counterparty, their_share);
        let (clsag, pseudo_out) = complete
            .complete(map)
            .map_err(|e| CosignError::Ceremony(e.to_string()))?;
        Ok((clsag, pseudo_out.compress().to_bytes()))
    }
}

/// This party's interpolated key-image share over the real output's key-image
/// generator: `scalar·b_i·x_i·Hp(P)`, mirroring the algorithm's own
/// accumulation (the ephemeral key offset is added once at assembly).
fn interpolated_image_share(
    keys: &ThresholdKeys<Ed25519>,
    output_key: &Bytes32,
) -> Result<Bytes32, CosignError> {
    use core::ops::Deref as _;
    let binding = match keys.interpolation() {
        Interpolation::Constant(c) => {
            c[usize::from(u16::from(keys.params().i())) - 1]
        }
        Interpolation::Lagrange => return Err(CosignError::Ceremony(
            "expected MuSig constant interpolation for 2-of-2 keys".into(),
        )),
    };
    let hp = dfg::EdwardsPoint(Point::biased_hash(*output_key).into());
    let share = hp * (binding * keys.current_scalar() * keys.original_secret_share().deref());
    Ok(share.compress().to_bytes())
}

/// Assemble the joint key image from both parties' interpolated shares plus
/// the output's key offset: `I = Σ shares + offset·Hp(P)`.
pub fn assemble_key_image(
    output_key: &Bytes32,
    key_offset: &Bytes32,
    shares: &[Bytes32],
) -> Result<Bytes32, CosignError> {
    let hp: curve25519_dalek::EdwardsPoint = Point::biased_hash(*output_key).into();
    let mut image = hp * scalar(key_offset)?;
    for s in shares {
        let p = curve25519_dalek::edwards::CompressedEdwardsY(*s)
            .decompress()
            .ok_or(CosignError::InvalidKey)?;
        image += p;
    }
    Ok(image.compress().to_bytes())
}

/// Drive a full 2-of-2 ceremony in-process (tests / same-host signing).
/// Returns the CLSAG, the joint key image (assembled from both parties'
/// public shares), and the ceremony's pseudo-out commitment.
pub fn cosign_in_process(
    spend: &StateSpend,
    keys: Vec<ThresholdKeys<Ed25519>>,
) -> Result<(Clsag, Bytes32, Bytes32), CosignError> {
    assert_eq!(keys.len(), 2, "2-of-2 ceremony");
    let participants: Vec<Participant> = keys.iter().map(|k| k.params().i()).collect();
    // keys[0] = taker (completes), keys[1] = maker (must NOT complete) — audit #2.
    let mut a = Cosigner::with_role(spend, keys[0].clone(), true)?;
    let mut b = Cosigner::with_role(spend, keys[1].clone(), false)?;

    let image = assemble_key_image(
        &spend.ring[spend.real_index][0],
        &spend.key_offset,
        &[a.key_image_share(), b.key_image_share()],
    )?;

    let pre_a = a.preprocess()?;
    let pre_b = b.preprocess()?;
    let share_a = a.share(participants[1], &pre_b, &spend.msg)?;
    let share_b = b.share(participants[0], &pre_a, &spend.msg)?;
    // Only the taker (a) completes; the maker (b) delivered its share to the
    // taker and never itself produces a broadcastable CLSAG (audit #2).
    let _ = &share_a;
    let (clsag_a, pseudo_a) = a.finish(participants[1], &share_b)?;
    Ok((clsag_a, image, pseudo_a))
}

/// Verify a CLSAG produced by [`cosign_in_process`] / the two-party flow.
pub fn verify_clsag(
    clsag: &Clsag,
    ring: &[[Bytes32; 2]],
    key_image: &Bytes32,
    pseudo_out: &Bytes32,
    msg: &[u8; 32],
) -> bool {
    let ring: Vec<[CompressedPoint; 2]> = ring
        .iter()
        .map(|[k, c]| [CompressedPoint::from(*k), CompressedPoint::from(*c)])
        .collect();
    clsag
        .verify(
            ring,
            &CompressedPoint::from(*key_image),
            &CompressedPoint::from(*pseudo_out),
            msg,
        )
        .is_ok()
}

/// The joint key image for an output, computable only with both secrets —
/// exposed for tests that cross-check the ceremony against first principles.
pub fn expected_key_image(
    output_key: &Bytes32,
    full_private_key: &curve25519_dalek::Scalar,
) -> Bytes32 {
    (Point::biased_hash(*output_key).into() * full_private_key)
        .compress()
        .to_bytes()
}
