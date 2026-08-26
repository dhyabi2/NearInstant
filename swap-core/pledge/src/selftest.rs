//! In-process self-test of the bilateral grief-bond mechanic (H-series) — the
//! anti-grief primitive an always-on maker needs: both parties pre-sign each
//! party's early-exit chain, so leaving early pays the *staying* counterparty
//! the penalty (non-racily, via the leaver broadcasting their own chain). This
//! mirrors the battery `early_exit` path but is callable from `src` so it can be
//! exposed to the browser via wasm (`wasm-bridge::pledge_selftest`).

use std::collections::BTreeMap;

use rand::rngs::OsRng;

use nano_ceremony::Bytes32;
use signing::{keys, Identifier};

use crate::bond::{exit_chain, sign_chain, Party};
use crate::terms::Terms;

/// Build a 2-of-2 bond, pre-sign BOTH parties' early-exit chains, and verify each
/// chain's joint signatures against the bond account. Returns true iff both
/// pre-signed exit chains verify — the property the grief bond relies on (a
/// leaver can always broadcast their own penalty-bearing exit).
pub fn pledge_selftest() -> bool {
    let terms = Terms { principal_a: 1_000, principal_b: 1_000, penalty_bps: 1_000, start: 0, maturity: 1_000 };
    if terms.validate().is_err() {
        return false;
    }
    let Ok((shares, pubkeys)) =
        keys::generate_with_dealer(2, 2, keys::IdentifierList::Default, &mut OsRng)
    else {
        return false;
    };
    let mut key_packages: BTreeMap<Identifier, keys::KeyPackage> = BTreeMap::new();
    for (id, s) in shares {
        let Ok(kp) = keys::KeyPackage::try_from(s) else { return false };
        key_packages.insert(id, kp);
    }
    let Ok(vk) = pubkeys.verifying_key().serialize() else { return false };
    let Ok(account) = <Bytes32>::try_from(vk) else { return false };
    let frontier: Bytes32 = [0x11u8; 32]; // any frontier; verify checks signatures
    let dest_a: Bytes32 = [0xA1u8; 32];
    let dest_b: Bytes32 = [0xB1u8; 32];

    let a_exit = exit_chain(&terms, account, frontier, account, Party::A, dest_a, dest_b);
    let b_exit = exit_chain(&terms, account, frontier, account, Party::B, dest_a, dest_b);
    let Ok(a_chain) = sign_chain(&a_exit, &key_packages, &pubkeys, &mut OsRng) else { return false };
    let Ok(b_chain) = sign_chain(&b_exit, &key_packages, &pubkeys, &mut OsRng) else { return false };
    a_chain.verify(&account) && b_chain.verify(&account)
}
