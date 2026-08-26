//! Early-adopter reputation (EA register) — a sybil-resistant, capital-backed
//! score bound to a trading key, computed purely from public on-chain evidence
//! (the transparent Nano leg + the G-series settled-swap ledger). No server, no
//! oracle, no admin scoring: every client recomputes the same number from the
//! same public records.
//!
//! Score = Σ(ln(1+capital) · time_held · recency) × diversity_ratio
//!
//! - **ln(1+capital) · time_held** — real value at stake over real duration,
//!   but capital enters SUB-LINEARLY (natural log) so a late WHALE cannot buy
//!   its way past an early, loyal small provider. A 1000× larger stake earns
//!   only ~10× the standing, and even that is dwarfed by sustained time. This
//!   is the whale-resistance fix: whales still earn MORE in absolute terms
//!   (earnings scale with the VOLUME they fill, not with reputation) — but
//!   reputation governs PREFERENCE/priority, and priority must not be for sale.
//!   Faking N "early" accounts still costs N× the locked capital-time, so the
//!   sybil floor holds; the log only caps how much raw size can dominate.
//! - **recency = e^(−λ · age)** — standing must be *maintained*, not farmed
//!   once and abandoned; old contributions decay toward zero.
//! - **diversity_ratio = unique_counterparties ÷ total_contributions** —
//!   rewards spreading across distinct real peers and penalises concentration:
//!   a Sybil wash-trading repeatedly with its own account has few unique peers
//!   over many contributions, so the ratio collapses toward zero. Honest
//!   trading with many distinct peers keeps the ratio near 1.
//!
//! This module is the pure scoring function over a list of settled
//! contributions. Harvesting those contributions from the Nano ledger + the
//! G-series `ledger` is thin integration on top; the score itself is
//! deterministic and unit-tested.

/// One settled contribution as read from public records: capital locked, how
/// long it was held, when it settled, and the counterparty it was with.
#[derive(Clone, Copy, Debug)]
pub struct Contribution {
    /// Capital at stake in raw (Nano) units.
    pub capital_raw: u128,
    /// Seconds the capital was held in the joint account.
    pub held_secs: u64,
    /// Age of this contribution now, in seconds (0 = just settled).
    pub age_secs: u64,
    /// A stable id for the counterparty (e.g. their account hash) — used only
    /// to count *distinct* peers, never revealed.
    pub counterparty: [u8; 32],
}

/// Reputation-scoring parameters. `decay_halflife_secs` sets how fast old
/// contributions fade (λ = ln2 / halflife); `capital_scale` keeps the raw
/// capital·time product in a sane numeric range.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    pub decay_halflife_secs: f64,
    pub capital_scale: f64,
}

impl Default for Params {
    fn default() -> Self {
        // 90-day half-life; scale raw·seconds down to a readable range.
        Self { decay_halflife_secs: 90.0 * 24.0 * 3600.0, capital_scale: 1e33 }
    }
}

/// Compute the reputation score for a set of contributions. Deterministic:
/// same inputs → same score on every client. Returns 0.0 for no contributions.
pub fn score(contributions: &[Contribution], p: &Params) -> f64 {
    if contributions.is_empty() {
        return 0.0;
    }
    let lambda = std::f64::consts::LN_2 / p.decay_halflife_secs.max(1.0);
    let mut weighted = 0.0f64;
    let mut peers = std::collections::BTreeSet::new();
    for c in contributions {
        // Capital enters sub-linearly (natural log) so raw size cannot dominate
        // standing — the whale-resistance property. Time stays linear, so
        // sustained commitment out-earns a large latecomer.
        let capital_units = c.capital_raw as f64 / p.capital_scale;
        let capital_time = (1.0 + capital_units).ln() * (c.held_secs as f64);
        let recency = (-lambda * c.age_secs as f64).exp();
        weighted += capital_time * recency;
        peers.insert(c.counterparty);
    }
    // Diversity ratio in (0,1]: 1 when every contribution is with a distinct
    // peer, collapsing toward 0 as trades concentrate on few peers (wash).
    let diversity = peers.len() as f64 / contributions.len() as f64;
    weighted * diversity
}

/// A discrete standing tier derived from the score — makers use tiers to decide
/// how much to favour a key (better rate, priority, higher limits). Tiers keep
/// the benefit coarse and legible; the raw score stays continuous underneath.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    None,
    Bronze,
    Silver,
    Gold,
    Founder,
}

/// Map a score to a tier. Thresholds are conventions every client shares.
pub fn tier(score: f64) -> Tier {
    match score {
        s if s >= 1000.0 => Tier::Founder,
        s if s >= 100.0 => Tier::Gold,
        s if s >= 10.0 => Tier::Silver,
        s if s >= 1.0 => Tier::Bronze,
        _ => Tier::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contrib(cap: u128, held: u64, age: u64, cp: u8) -> Contribution {
        Contribution { capital_raw: cap, held_secs: held, age_secs: age, counterparty: [cp; 32] }
    }

    #[test]
    fn more_capital_and_time_scores_higher() {
        let p = Params::default();
        let small = score(&[contrib(1_000_000_000_000_000_000_000_000_000_000, 3600, 0, 1)], &p);
        let big = score(&[contrib(1_000_000_000_000_000_000_000_000_000_000, 7200, 0, 1)], &p);
        assert!(big > small, "twice the hold time scores higher");
        let richer = score(&[contrib(2_000_000_000_000_000_000_000_000_000_000, 3600, 0, 1)], &p);
        assert!(richer > small, "twice the capital scores higher");
    }

    #[test]
    fn recency_decay_fades_old_contributions() {
        let p = Params::default();
        let fresh = score(&[contrib(1u128 << 100, 3600, 0, 1)], &p);
        let old = score(&[contrib(1u128 << 100, 3600, (180 * 24 * 3600) as u64, 1)], &p);
        assert!(old < fresh, "a 180-day-old contribution scores well below a fresh one");
        // At two half-lives (~180d) it should be ~1/4.
        assert!(old < fresh * 0.30 && old > fresh * 0.20, "≈ quarter after two half-lives");
    }

    #[test]
    fn self_dealing_is_divided_out() {
        let p = Params::default();
        let c = 1u128 << 100;
        // Honest: 4 distinct counterparties.
        let honest = score(
            &[contrib(c, 3600, 0, 1), contrib(c, 3600, 0, 2), contrib(c, 3600, 0, 3), contrib(c, 3600, 0, 4)],
            &p,
        );
        // Wash: 4 contributions but all with the SAME single counterparty.
        let wash = score(
            &[contrib(c, 3600, 0, 9), contrib(c, 3600, 0, 9), contrib(c, 3600, 0, 9), contrib(c, 3600, 0, 9)],
            &p,
        );
        assert!(honest > wash * 3.5, "spreading across distinct peers scores far higher than wash trading");
    }

    #[test]
    fn late_whale_cannot_leapfrog_early_loyal_small_lp() {
        // The whale-resistance property (protects small/early providers): a
        // late-arriving whale with 1000x the capital but only just arrived must
        // NOT outrank an early provider who has stayed and served many peers.
        let p = Params::default();
        let day = 24 * 3600u64;
        let one_xno = 10u128.pow(30); // ~1 XNO in raw Nano units

        // Early, loyal small LP: 100 XNO, held 100 days, across 20 distinct peers.
        let mut small = Vec::new();
        for i in 0..20u8 {
            small.push(contrib(100 * one_xno, 100 * day, 0, i + 1));
        }
        // Late whale: 100,000 XNO (1000x more capital), just 1 day, one peer.
        let whale = vec![contrib(100_000 * one_xno, day, 0, 99)];

        let s_small = score(&small, &p);
        let s_whale = score(&whale, &p);
        assert!(
            s_small > s_whale,
            "early loyal small LP ({s_small:.0}) must outrank the late whale ({s_whale:.0})"
        );

        // And a 1000x capital gap must compress to far less than 1000x standing
        // (the sub-linear-capital guarantee): compare like-for-like (same time,
        // same single peer) — the whale's edge should be modest, not 1000x.
        let poor = score(&[contrib(100 * one_xno, day, 0, 1)], &p);
        let rich = score(&[contrib(100_000 * one_xno, day, 0, 1)], &p);
        assert!(rich > poor, "more capital still helps (fair to honest large LPs)");
        assert!(rich < poor * 100.0, "but 1000x capital buys <100x standing, not 1000x");
    }

    #[test]
    fn empty_is_zero_and_tiers_are_ordered() {
        assert_eq!(score(&[], &Params::default()), 0.0);
        assert_eq!(tier(0.0), Tier::None);
        assert!(Tier::Founder > Tier::Gold && Tier::Gold > Tier::Silver);
        assert_eq!(tier(5000.0), Tier::Founder);
        assert_eq!(tier(50.0), Tier::Silver);
    }
}
