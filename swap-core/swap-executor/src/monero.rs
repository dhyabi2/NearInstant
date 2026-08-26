//! The Monero joint-account material and the real `XmrSide` implementation.
//!
//! The Monero leg of the atomic swap uses a DIFFERENT joint key than the Nano
//! leg: a MuSig-aggregated spend key + a shared view key (the I10 isolation
//! layer), encoded as a primary Monero address. [`JointXmr`] carries that
//! material; the two parties derive it identically after exchanging their
//! spend-pub and view contributions.
//!
//! The swap hinge: the Nano claim's adaptor point is Bob's XMR spend PUBLIC key
//! (`T = x·G`, with `x` = Bob's spend secret). When Bob settles the Nano leg he
//! reveals `x`, and Alice reconstructs the joint Monero spend secret via
//! [`monero_side::cosign::reconstruct_joint_secret`] — which she needs to sweep.
//!
//! [`MoneroLeg`] is the real `XmrSide`: it sweeps the joint output (the proven
//! `sweep_joint` path) and locks/verifies via the operator's `monero-wallet-rpc`.
//! It moves REAL value and is behind the `monero` feature + a `--live` gate; it
//! has NOT been exercised on mainnet.

use monero_side::isolation::{self, Bytes32};

/// The Monero network flavor (address encoding + node selection).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MoneroNet {
    Mainnet,
    Stagenet,
}

impl From<MoneroNet> for isolation::Net {
    fn from(n: MoneroNet) -> Self {
        match n {
            MoneroNet::Mainnet => isolation::Net::Mainnet,
            MoneroNet::Stagenet => isolation::Net::Stagenet,
        }
    }
}

/// Everything both parties agree on about the joint Monero account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JointXmr {
    /// Session context (domain separation for the MuSig aggregation).
    pub context: Bytes32,
    /// Both spend public keys, SORTED (canonical order, agreed by both).
    pub spend_pubs: Vec<Bytes32>,
    /// The MuSig joint spend public key.
    pub spend_pub: Bytes32,
    /// The shared private view key (both parties' view contributions).
    pub view_key: Bytes32,
    /// The encoded joint primary address (e.g. mainnet `4…`).
    pub address: String,
}

/// Errors deriving the joint account.
#[derive(Debug, PartialEq, Eq)]
pub enum JointError {
    /// The spend pubs or view contributions are malformed.
    Malformed,
}

impl JointXmr {
    /// Derive the joint account from both parties' contributions. `spend_pubs`
    /// must already be sorted (both parties agree on order); `view_a`/`view_b`
    /// are the two view-key contributions (order-independent).
    pub fn derive(
        context: Bytes32,
        mut spend_pubs: Vec<Bytes32>,
        view_a: &Bytes32,
        view_b: &Bytes32,
        net: MoneroNet,
    ) -> Result<Self, JointError> {
        if spend_pubs.len() != 2 {
            return Err(JointError::Malformed);
        }
        spend_pubs.sort();
        let spend_pub = isolation::aggregate_spend(context, &spend_pubs).ok_or(JointError::Malformed)?;
        let view_key = isolation::shared_view_key(context, view_a, view_b);
        let address = isolation::joint_address(&spend_pub, &view_key, net.into())
            .ok_or(JointError::Malformed)?;
        Ok(Self {
            context,
            spend_pubs,
            spend_pub,
            view_key,
            address,
        })
    }
}
