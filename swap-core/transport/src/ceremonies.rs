//! Wire-driven two-party ceremonies: each function is ONE party's side,
//! symmetric — both parties call the same function with their own material
//! and connected wires, and both arrive at the identical verified output.

use std::collections::BTreeMap;

use rand_core::OsRng;

use nano_ceremony::block::StateBlock;
use signing::adaptor::{
    adaptor_sign, aggregate_presignature, AdaptorSession, PreSignature,
};
use signing::{keys, round1, round2, Identifier, SigningPackage};

use crate::{recv_frame, send_frame, tag, Wire, WireError};

fn my_id(kp: &keys::KeyPackage) -> Identifier {
    *kp.identifier()
}

fn their_id(pubkeys: &keys::PublicKeyPackage, me: Identifier) -> Result<Identifier, WireError> {
    pubkeys
        .verifying_shares()
        .keys()
        .copied()
        .find(|id| *id != me)
        .ok_or(WireError::Malformed)
}

/// Two-party distributed keygen over the wire (no trusted dealer). Both
/// parties call this with their own `my_identifier` and the counterparty's
/// `their_identifier` (by convention 1 = Alice/XNO seller, 2 = Bob/XMR
/// seller); both return their own [`keys::KeyPackage`] and the IDENTICAL
/// shared [`keys::PublicKeyPackage`]. Neither party learns the other's share,
/// so neither ever holds a general key that could drain the joint account.
pub fn keygen_over_wire(
    wire: &impl Wire,
    my_identifier: Identifier,
    their_identifier: Identifier,
) -> Result<(keys::KeyPackage, keys::PublicKeyPackage), WireError> {
    // Round 1: exchange public DKG packages.
    let (r1_secret, r1_pkg) =
        keys::dkg::part1(my_identifier, OsRng).map_err(|_| WireError::BadContribution)?;
    send_frame(
        wire,
        tag::DKG_ROUND1,
        &r1_pkg.serialize().map_err(|_| WireError::Malformed)?,
    )?;
    let their_r1_bytes = recv_frame(wire, tag::DKG_ROUND1)?;
    let their_r1 =
        keys::dkg::Round1Package::deserialize(&their_r1_bytes).map_err(|_| WireError::Malformed)?;
    let mut r1_map = BTreeMap::new();
    r1_map.insert(their_identifier, their_r1);

    // Round 2: exchange the round-2 package addressed to the other party.
    let (r2_secret, r2_map) =
        keys::dkg::part2(r1_secret, &r1_map).map_err(|_| WireError::BadContribution)?;
    let mine_for_them = r2_map.get(&their_identifier).cloned().ok_or(WireError::Malformed)?;
    send_frame(
        wire,
        tag::DKG_ROUND2,
        &mine_for_them.serialize().map_err(|_| WireError::Malformed)?,
    )?;
    let their_r2_bytes = recv_frame(wire, tag::DKG_ROUND2)?;
    let their_r2 =
        keys::dkg::Round2Package::deserialize(&their_r2_bytes).map_err(|_| WireError::Malformed)?;
    let mut r2_map = BTreeMap::new();
    r2_map.insert(their_identifier, their_r2);

    // Round 3 (local): assemble the key package + shared public key package.
    keys::dkg::part3(&r2_secret, &r1_map, &r2_map).map_err(|_| WireError::BadContribution)
}

/// Round 1 exchange: commit locally, swap serialized commitments, return the
/// full commitment map plus our nonces.
fn exchange_commitments(
    wire: &impl Wire,
    kp: &keys::KeyPackage,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<
    (
        round1::SigningNonces,
        BTreeMap<Identifier, round1::SigningCommitments>,
    ),
    WireError,
> {
    let (nonces, my_comms) = round1::commit(kp.signing_share(), &mut OsRng);
    let ser = my_comms.serialize().map_err(|_| WireError::Malformed)?;
    send_frame(wire, tag::COMMITMENTS, &ser)?;
    let theirs_bytes = recv_frame(wire, tag::COMMITMENTS)?;
    let theirs =
        round1::SigningCommitments::deserialize(&theirs_bytes).map_err(|_| WireError::Malformed)?;
    let mut map = BTreeMap::new();
    map.insert(my_id(kp), my_comms);
    map.insert(their_id(pubkeys, my_id(kp))?, theirs);
    Ok((nonces, map))
}

/// Jointly sign a Nano block over the wire. Both parties call this; both
/// return the same aggregated, locally-verified 64-byte signature.
pub fn sign_block_over_wire(
    wire: &impl Wire,
    block: &StateBlock,
    kp: &keys::KeyPackage,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<[u8; 64], WireError> {
    let (nonces, comms) = exchange_commitments(wire, kp, pubkeys)?;
    let hash = block.hash();
    let package = SigningPackage::new(comms, &hash);

    let my_share = round2::sign(&package, &nonces, kp).map_err(|_| WireError::BadContribution)?;
    send_frame(wire, tag::SIG_SHARE, &my_share.serialize())?;
    let their_bytes = recv_frame(wire, tag::SIG_SHARE)?;
    let their_share =
        round2::SignatureShare::deserialize(&their_bytes).map_err(|_| WireError::Malformed)?;

    let mut shares = BTreeMap::new();
    shares.insert(my_id(kp), my_share);
    shares.insert(their_id(pubkeys, my_id(kp))?, their_share);
    // aggregate() verifies the final signature and identifies a culprit on
    // failure — a bad counterparty share surfaces here.
    let sig = signing::aggregate(&package, &shares, pubkeys)
        .map_err(|_| WireError::BadContribution)?;
    let bytes: [u8; 64] = sig
        .serialize()
        .map_err(|_| WireError::Malformed)?
        .try_into()
        .map_err(|_| WireError::Malformed)?;
    // Belt and braces: Nano semantics.
    let account: [u8; 32] = pubkeys
        .verifying_key()
        .serialize()
        .map_err(|_| WireError::Malformed)?
        .try_into()
        .map_err(|_| WireError::Malformed)?;
    if !signing::nano_verify::verify(&account, &hash, &bytes) {
        return Err(WireError::BadContribution);
    }
    Ok(bytes)
}

/// Jointly produce an adaptor pre-signature on a block over the wire.
/// Both parties verify each other's share against the session transcript
/// (inside `aggregate_presignature`) and return the identical pre-signature.
pub fn adaptor_presign_over_wire(
    wire: &impl Wire,
    block: &StateBlock,
    adaptor_point: &[u8; 32],
    kp: &keys::KeyPackage,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<PreSignature, WireError> {
    let (nonces, comms) = exchange_commitments(wire, kp, pubkeys)?;
    let hash = block.hash();
    let session =
        AdaptorSession::new(comms, &hash, adaptor_point).map_err(|_| WireError::Malformed)?;

    let my_share = adaptor_sign(&session, &nonces, kp).map_err(|_| WireError::BadContribution)?;
    send_frame(wire, tag::SIG_SHARE, &my_share.serialize())?;
    let their_bytes = recv_frame(wire, tag::SIG_SHARE)?;
    let their_share =
        round2::SignatureShare::deserialize(&their_bytes).map_err(|_| WireError::Malformed)?;

    let mut shares = BTreeMap::new();
    shares.insert(my_id(kp), my_share);
    shares.insert(their_id(pubkeys, my_id(kp))?, their_share);
    aggregate_presignature(&session, &shares, pubkeys).map_err(|_| WireError::BadContribution)
}

/// Which side of the channel co-signing this party is. Audit #2: the one-way
/// channel is safe ONLY if the taker's signature share never crosses to the
/// maker. The taker completes (holds the state); the maker send-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CosignRole {
    Taker,
    Maker,
}

/// Co-sign one CLSAG state spend over the wire, role-asymmetric.
///
/// Round 1 (symmetric): exchange preprocess + key-image share.
/// Round 2 (ASYMMETRIC): the MAKER sends its signature share and stops — it
/// never receives the taker's share and never completes. The TAKER receives
/// the maker's share and completes, obtaining the broadcastable CLSAG. This
/// enforces the one-way-channel invariant on the wire: the maker can never
/// assemble a state to hoard (audit #2, break-pass BREAK #1).
///
/// Returns `(Some(clsag), image, pseudo)` for the taker, `(None, image,
/// pseudo)` for the maker.
pub fn clsag_cosign_over_wire(
    wire: &impl Wire,
    spend: &monero_side::cosign::StateSpend,
    my_keys: modular_frost::ThresholdKeys<modular_frost::curve::Ed25519>,
    their_participant: modular_frost::Participant,
    role: CosignRole,
) -> Result<(Option<monero_clsag::Clsag>, [u8; 32], [u8; 32]), WireError> {
    let mut me = monero_side::cosign::Cosigner::with_role(spend, my_keys, role == CosignRole::Taker)
        .map_err(|_| WireError::Malformed)?;

    // Round 1: preprocess + key-image share, framed together.
    let my_pre = me.preprocess().map_err(|_| WireError::Malformed)?;
    let mut payload = me.key_image_share().to_vec();
    payload.extend_from_slice(&my_pre);
    send_frame(wire, tag::CLSAG_PREPROCESS, &payload)?;
    let theirs = recv_frame(wire, tag::CLSAG_PREPROCESS)?;
    if theirs.len() < 32 {
        return Err(WireError::Malformed);
    }
    let their_image_share: [u8; 32] = theirs[..32].try_into().unwrap();
    let their_pre = &theirs[32..];
    let my_image_share = me.key_image_share();

    // Both compute their signature share (needs the counterparty preprocess).
    let my_share = me
        .share(their_participant, their_pre, &spend.msg)
        .map_err(|_| WireError::BadContribution)?;

    // Assemble the joint key image (both sides, from public shares).
    let image = monero_side::cosign::assemble_key_image(
        &spend.ring[spend.real_index][0],
        &spend.key_offset,
        &[my_image_share, their_image_share],
    )
    .map_err(|_| WireError::BadContribution)?;
    let pseudo_out = spend
        .pseudo_out()
        .ok_or(WireError::Malformed)?;

    match role {
        CosignRole::Maker => {
            // Send-only: hand the share to the taker, never receive theirs,
            // never complete. The maker holds no broadcastable state.
            send_frame(wire, tag::CLSAG_SHARE, &my_share)?;
            Ok((None, image, pseudo_out))
        }
        CosignRole::Taker => {
            // Receive the maker's share and complete; do NOT send ours.
            let their_share = recv_frame(wire, tag::CLSAG_SHARE)?;
            let (clsag, pseudo) = me
                .finish(their_participant, &their_share)
                .map_err(|_| WireError::BadContribution)?;
            if !monero_side::cosign::verify_clsag(&clsag, &spend.ring, &image, &pseudo, &spend.msg) {
                return Err(WireError::BadContribution);
            }
            Ok((Some(clsag), image, pseudo))
        }
    }
}
