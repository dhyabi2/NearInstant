//! Live Monero daemon RPC over public nodes (no local `monerod`).
//!
//! Wraps `monero-simple-request-rpc` so the rest of `swap-core` talks to a
//! public mainnet/stagenet node over HTTP(S) instead of requiring a local
//! daemon. The URL selects the network — pass a mainnet node or a
//! stagenet/testnet node and the identical client drives every flavor.
//!
//! The swap's happy path only needs the live fee estimate ([`Node::fee_tiers`]);
//! everything else (block scanning, decoy selection, output lookup,
//! broadcasting) is reached through [`Node::as_raw`]'s package traits.

use monero_simple_request_rpc::prelude::{
    FeeError, FeePriority, InterfaceError, MoneroDaemon, ProvidesFeeRates,
};
use monero_simple_request_rpc::SimpleRequestTransport;

use crate::fee::FeeRate;

/// Public mainnet Monero node used when `MONERO_RPC_URL` is unset. Any public
/// node (e.g. `node.monerodevs.org:18089`) or a local `http://127.0.0.1:18081`
/// can be substituted via the environment variable.
pub const DEFAULT_MAINNET_RPC_URL: &str = "https://xmr-node.cakewallet.com:18081";

/// Independent second mainnet node (different operator) for confirmation
/// quorums — a settlement-grade maturity check must never rest on one
/// daemon's word. TLS + CORS verified 2026-08-23.
pub const ALT_MAINNET_RPC_URL: &str = "https://node.sethforprivacy.com";

/// A connected Monero daemon client (HTTP(S) JSON-RPC).
#[derive(Clone)]
pub struct Node {
    raw: MoneroDaemon<SimpleRequestTransport>,
}

impl Node {
    /// Connect to `url` over HTTP(S). Digest-auth nodes may embed credentials
    /// as `scheme://user:pass@host:port`.
    pub async fn connect(url: &str) -> Result<Self, Error> {
        let raw = SimpleRequestTransport::new(url.to_string())
            .await
            .map_err(Error::Interface)?;
        Ok(Self { raw })
    }

    /// Connect to `MONERO_RPC_URL`, falling back to [`DEFAULT_MAINNET_RPC_URL`].
    pub async fn connect_env() -> Result<Self, Error> {
        let url = std::env::var("MONERO_RPC_URL")
            .unwrap_or_else(|_| DEFAULT_MAINNET_RPC_URL.to_string());
        Self::connect(&url).await
    }

    /// The underlying package client, exposing block scanning, decoy selection,
    /// output lookup and `publish_transaction` via its `prelude` traits.
    pub fn as_raw(&self) -> &MoneroDaemon<SimpleRequestTransport> {
        &self.raw
    }

    /// The four-tier `get_fee_estimate` (piconero/weight for `Low`..`Highest`)
    /// plus its quantization mask, mapped onto our [`FeeRate`]. Queries all
    /// four priorities so the caller has a full, fresh, settlement-time rate.
    pub async fn fee_tiers(&self) -> Result<FeeRate, Error> {
        let base = self
            .raw
            .fee_rate(FeePriority::Unimportant, u64::MAX)
            .await
            .map_err(Error::Fee)?;
        let mut per_weight = [0u64; 4];
        per_weight[0] = base.per_weight();
        for (i, p) in [FeePriority::Normal, FeePriority::Elevated, FeePriority::Priority]
            .iter()
            .enumerate()
        {
            per_weight[i + 1] = self
                .raw
                .fee_rate(*p, u64::MAX)
                .await
                .map_err(Error::Fee)?
                .per_weight();
        }
        Ok(FeeRate {
            per_weight,
            quantization_mask: mask_of(&base),
        })
    }
}

/// Extract the quantization mask from the package's serialized fee rate
/// (16 bytes: `per_weight` LE followed by `mask` LE).
fn mask_of(r: &monero_simple_request_rpc::prelude::FeeRate) -> u64 {
    let s = r.serialize();
    let mut m = [0u8; 8];
    m.copy_from_slice(&s[8..16]);
    u64::from_le_bytes(m)
}

/// Errors from connecting to and querying a Monero node.
#[derive(Debug)]
pub enum Error {
    /// The transport/interface layer rejected the connection or request.
    Interface(InterfaceError),
    /// The node returned an invalid fee estimate.
    Fee(FeeError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Interface(e) => write!(f, "monero node RPC error: {e:?}"),
            Error::Fee(e) => write!(f, "monero fee estimate error: {e:?}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::mask_of;
    use monero_simple_request_rpc::prelude::FeeRate as RpcFeeRate;

    #[test]
    fn mask_of_recovers_the_quantization_mask() {
        let r = RpcFeeRate::new(123_456, 10_000).expect("valid rate");
        assert_eq!(mask_of(&r), 10_000);
    }
}
