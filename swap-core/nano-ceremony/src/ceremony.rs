//! Joint signing of Nano block hashes over the `signing` crate.
//!
//! The message a Nano node verifies is the 32-byte block hash; these helpers
//! bind the FROST/adaptor ceremonies to [`crate::block::StateBlock::hash`].
//! They take all participants' materials at once — the in-process shape used
//! by tests and by the swap state machine once transport (Block 4+) delivers
//! the counterparty's halves.

use std::collections::BTreeMap;

use signing::adaptor::{
    adaptor_sign, aggregate_presignature, AdaptorError, AdaptorSession, PreSignature,
};
use signing::{keys, round1, round2, Identifier, SigningPackage};

use crate::block::{SignedBlock, StateBlock};

/// Jointly sign a state block with every participant's nonces and key
/// package, returning the aggregated Nano-valid signature.
pub fn sign_block(
    block: &StateBlock,
    commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    nonces: &BTreeMap<Identifier, round1::SigningNonces>,
    key_packages: &BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<[u8; 64], signing::Error> {
    let hash = block.hash();
    let package = SigningPackage::new(commitments, &hash);
    let mut shares = BTreeMap::new();
    for (id, kp) in key_packages {
        shares.insert(*id, round2::sign(&package, &nonces[id], kp)?);
    }
    let sig = signing::aggregate(&package, &shares, pubkeys)?;
    Ok(sig
        .serialize()?
        .as_slice()
        .try_into()
        .expect("ed25519 signatures are 64 bytes"))
}

/// Jointly produce an adaptor *pre-signature* on a state block for adaptor
/// point `T`. The pre-signature is not broadcastable; completing it with the
/// adaptor secret yields the valid block signature, and the broadcast of that
/// signature reveals the secret to the pre-signature holder.
pub fn adaptor_presign_block(
    block: &StateBlock,
    adaptor_point: &[u8; 32],
    commitments: BTreeMap<Identifier, round1::SigningCommitments>,
    nonces: &BTreeMap<Identifier, round1::SigningNonces>,
    key_packages: &BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
) -> Result<PreSignature, AdaptorError> {
    let hash = block.hash();
    let session = AdaptorSession::new(commitments, &hash, adaptor_point)?;
    let mut shares = BTreeMap::new();
    for (id, kp) in key_packages {
        shares.insert(*id, adaptor_sign(&session, &nonces[id], kp)?);
    }
    aggregate_presignature(&session, &shares, pubkeys)
}

/// Attach a signature and work to a block.
pub fn assemble(block: StateBlock, signature: [u8; 64], work: u64) -> SignedBlock {
    SignedBlock {
        block,
        signature,
        work,
    }
}
