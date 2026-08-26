//! The bond construction: chains, ceremonies, escrows, recovery.

use std::collections::BTreeMap;

use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};

use nano_ceremony::block::{SignedBlock, StateBlock, Subtype};
use nano_ceremony::{ceremony, work, Bytes32};
use puzzle_escrow::escrow::{self, EscrowPublic, EscrowSecret};
use signing::adaptor::{complete_presignature, PreSignature};
use signing::{keys, round1, Identifier};

use crate::terms::Terms;

/// Which party.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    A,
    B,
}

/// One fully pre-signed two-block chain (both blocks joint-signed; work is
/// attached at broadcast time since the roots are known).
#[derive(Clone, Debug)]
pub struct SignedChain {
    pub blocks: [StateBlock; 2],
    pub signatures: [[u8; 64]; 2],
}

impl SignedChain {
    /// Attach work and produce broadcastable blocks (N4: roots known ahead).
    pub fn assemble(&self, threshold: u64) -> [SignedBlock; 2] {
        [
            ceremony::assemble(
                self.blocks[0].clone(),
                self.signatures[0],
                work::generate(&self.blocks[0].work_root(), threshold, 0),
            ),
            ceremony::assemble(
                self.blocks[1].clone(),
                self.signatures[1],
                work::generate(&self.blocks[1].work_root(), threshold, 0),
            ),
        ]
    }

    /// Verify both signatures and the chain linkage.
    pub fn verify(&self, account: &Bytes32) -> bool {
        self.blocks[1].previous == self.blocks[0].hash()
            && signing::nano_verify::verify(account, &self.blocks[0].hash(), &self.signatures[0])
            && signing::nano_verify::verify(account, &self.blocks[1].hash(), &self.signatures[1])
    }
}

/// Build the two-block chain for `leaver` exiting early from `frontier`:
/// block 1 pays the stayer (their principal + the leaver's FULL penalty),
/// block 2 returns the remainder to the leaver, emptying the account.
pub fn exit_chain(
    terms: &Terms,
    account: Bytes32,
    frontier: Bytes32,
    representative: Bytes32,
    leaver: Party,
    dest_a: Bytes32,
    dest_b: Bytes32,
) -> [StateBlock; 2] {
    let (leaver_principal, stayer_principal, stayer_dest, leaver_dest) = match leaver {
        Party::A => (terms.principal_a, terms.principal_b, dest_b, dest_a),
        Party::B => (terms.principal_b, terms.principal_a, dest_a, dest_b),
    };
    let penalty = terms.full_penalty(leaver_principal);
    let to_stayer = stayer_principal + penalty;
    let total = terms.total();
    let b1 = StateBlock {
        account,
        previous: frontier,
        representative,
        balance: total - to_stayer,
        link: stayer_dest,
        subtype: Subtype::Send,
    };
    let b2 = StateBlock {
        account,
        previous: b1.hash(),
        representative,
        balance: 0,
        link: leaver_dest,
        subtype: Subtype::Send,
    };
    [b1, b2]
}

/// The leaver's exit chain in the STREAMED variant (H5): block 1 pays the
/// stayer their principal immediately; block 2 returns the leaver's
/// remainder; the penalty stays on the joint account's balance, to be
/// released by the pre-signed drip chain (see [`crate::stream`]).
pub fn exit_chain_with_drip(
    terms: &Terms,
    account: Bytes32,
    frontier: Bytes32,
    representative: Bytes32,
    leaver: Party,
    dest_a: Bytes32,
    dest_b: Bytes32,
) -> [StateBlock; 2] {
    let (leaver_principal, stayer_principal, stayer_dest, leaver_dest) = match leaver {
        Party::A => (terms.principal_a, terms.principal_b, dest_b, dest_a),
        Party::B => (terms.principal_b, terms.principal_a, dest_a, dest_b),
    };
    let penalty = terms.full_penalty(leaver_principal);
    let total = terms.total();
    let b1 = StateBlock {
        account,
        previous: frontier,
        representative,
        balance: total - stayer_principal,
        link: stayer_dest,
        subtype: Subtype::Send,
    };
    let b2 = StateBlock {
        account,
        previous: b1.hash(),
        representative,
        balance: penalty, // the drip stays behind
        link: leaver_dest,
        subtype: Subtype::Send,
    };
    [b1, b2]
}

/// The clean maturity chain (NOT pre-signed at setup): principals returned,
/// no penalty. Signed cooperatively at maturity, or unilaterally after
/// escrow recovery.
pub fn maturity_chain(
    terms: &Terms,
    account: Bytes32,
    frontier: Bytes32,
    representative: Bytes32,
    dest_a: Bytes32,
    dest_b: Bytes32,
) -> [StateBlock; 2] {
    let b1 = StateBlock {
        account,
        previous: frontier,
        representative,
        balance: terms.principal_a,
        link: dest_b,
        subtype: Subtype::Send,
    };
    let b2 = StateBlock {
        account,
        previous: b1.hash(),
        representative,
        balance: 0,
        link: dest_a,
        subtype: Subtype::Send,
    };
    [b1, b2]
}

/// Jointly sign a chain (in-process ceremony helper; transport-split
/// signing uses the same `ceremony::sign_block` per block).
pub fn sign_chain<R: RngCore + CryptoRng>(
    chain: &[StateBlock; 2],
    key_packages: &BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
    rng: &mut R,
) -> Result<SignedChain, signing::Error> {
    let mut signatures = [[0u8; 64]; 2];
    for (i, block) in chain.iter().enumerate() {
        let mut nonces = BTreeMap::new();
        let mut comms = BTreeMap::new();
        for (id, kp) in key_packages {
            let (n, c) = round1::commit(kp.signing_share(), rng);
            nonces.insert(*id, n);
            comms.insert(*id, c);
        }
        signatures[i] = ceremony::sign_block(block, comms, &nonces, key_packages, pubkeys)?;
    }
    Ok(SignedChain {
        blocks: chain.clone(),
        signatures,
    })
}

/// Escrow this party's FROST signing share for the counterparty (the
/// maturity fallback). The share scalar rides the Block 5 cut-and-choose
/// escrow unchanged.
#[deprecated(note = "audit #5: escrows a raw FROST share; use escrow_maturity_secret + recover_maturity")]
pub fn escrow_share<R: RngCore + CryptoRng>(
    key_package: &keys::KeyPackage,
    m: usize,
    prime_bits: usize,
    t: u64,
    rng: &mut R,
) -> (EscrowPublic, EscrowSecret) {
    let bytes: [u8; 32] = key_package
        .signing_share()
        .serialize()
        .try_into()
        .expect("signing shares are 32 bytes");
    let share = Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .expect("FROST shares are canonical scalars");
    escrow::escrow_make(rng, &share, m, prime_bits, t)
}

/// After solving the counterparty's escrow: rebuild their key package and
/// reconstruct the full joint signing key (dealer 2-of-2 Lagrange), giving
/// unilateral signing power for the clean split.
#[deprecated(note = "audit #5: yields a GENERAL joint key (principal-theft); use recover_maturity")]
pub fn reconstruct_joint_key(
    my_package: &keys::KeyPackage,
    their_identifier: Identifier,
    their_share: &[u8; 32],
    pubkeys: &keys::PublicKeyPackage,
) -> Result<frost_core::SigningKey<signing::Ed25519Blake2b>, signing::Error> {
    let share = frost_core::keys::SigningShare::deserialize(their_share)?;
    let their_verifying = pubkeys
        .verifying_shares()
        .get(&their_identifier)
        .ok_or(frost_core::Error::UnknownIdentifier)?;
    let their_package = keys::KeyPackage::new(
        their_identifier,
        share,
        *their_verifying,
        *pubkeys.verifying_key(),
        *my_package.min_signers(),
    );
    frost_core::keys::reconstruct(&[my_package.clone(), their_package])
}

/// Audit #5 - the SAFE maturity fallback. Instead of escrowing a raw FROST
/// share (which reconstructs a general signing key able to drain both
/// principals), adaptor-pre-sign the clean maturity split at setup with an
/// adaptor point T = t*G, and escrow only the scalar t. Recovery solves the
/// escrow for t and completes the pre-signatures - producing ONLY the
/// clean-split block signatures. An early solve yields at worst a
/// penalty-free clean exit, never theft.
pub fn adaptor_lock_maturity<R: RngCore + CryptoRng>(
    chain: &[StateBlock; 2],
    adaptor_secret: &Scalar,
    key_packages: &BTreeMap<Identifier, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
    rng: &mut R,
) -> Result<[PreSignature; 2], crate::MaturityError> {
    let t_point = (adaptor_secret
        * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let mut presigs = Vec::with_capacity(2);
    for block in chain.iter() {
        let mut nonces = BTreeMap::new();
        let mut comms = BTreeMap::new();
        for (id, kp) in key_packages {
            let (n, c) = round1::commit(kp.signing_share(), rng);
            nonces.insert(*id, n);
            comms.insert(*id, c);
        }
        let ps = ceremony::adaptor_presign_block(
            block, &t_point, comms, &nonces, key_packages, pubkeys,
        )
        .map_err(|_| crate::MaturityError::Presign)?;
        presigs.push(ps);
    }
    Ok([presigs[0], presigs[1]])
}

/// Escrow the maturity adaptor secret t (Block 5 cut-and-choose escrow).
pub fn escrow_maturity_secret<R: RngCore + CryptoRng>(
    adaptor_secret: &Scalar,
    m: usize,
    prime_bits: usize,
    t: u64,
    rng: &mut R,
) -> (EscrowPublic, EscrowSecret) {
    escrow::escrow_make(rng, adaptor_secret, m, prime_bits, t)
}

/// Recover the clean-split signatures after the counterparty vanished: solve
/// the escrow for the adaptor secret and complete BOTH maturity
/// pre-signatures. Yields only these two block signatures, never a general key.
pub fn recover_maturity(
    presigs: &[PreSignature; 2],
    escrow_public: &EscrowPublic,
    kept_index: usize,
) -> Result<[[u8; 64]; 2], crate::MaturityError> {
    let secret = escrow::escrow_solve(escrow_public, kept_index)
        .map_err(|_| crate::MaturityError::Escrow)?;
    let s0 = complete_presignature(&presigs[0], &secret.to_bytes())
        .map_err(|_| crate::MaturityError::Complete)?;
    let s1 = complete_presignature(&presigs[1], &secret.to_bytes())
        .map_err(|_| crate::MaturityError::Complete)?;
    Ok([s0, s1])
}

/// Sign a block hash with a reconstructed full key (single-signer path —
/// still an ordinary Nano-valid ed25519-blake2b signature).
#[deprecated(note = "audit #5: pairs with the unsafe reconstruct path; use recover_maturity")]
pub fn sign_block_unilateral<R: RngCore + CryptoRng>(
    key: &frost_core::SigningKey<signing::Ed25519Blake2b>,
    block: &StateBlock,
    rng: &mut R,
) -> [u8; 64] {
    key.sign(rng, &block.hash())
        .serialize()
        .expect("signature serializes")
        .try_into()
        .expect("64 bytes")
}

/// Bond lifecycle states for the client (drives UI + the G2 ledger labels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondState {
    /// Locked; only penalty chains are broadcastable.
    Active,
    /// A leaver's chain settled; the stayer's ledger books the penalty as
    /// "counterparty early-exit compensation" (H2 honesty rule).
    ExitedEarly { leaver: Party, penalty_paid: u128 },
    /// Clean split settled cooperatively at maturity.
    MaturedCooperative,
    /// Clean split settled unilaterally after escrow recovery.
    MaturedRecovered,
}
