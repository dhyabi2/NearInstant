//! The N3 horizon rule: no claim deadline may sit closer than half the
//! *worst-case-fast* solve time of the counterparty's puzzle.
//!
//! `deadline < T_target / (2 · S_max)` — STRICTLY. `T_target` is the wall
//! time the puzzle takes on the calibrating machine; `S_max` is the assumed
//! maximum sequential-speed advantage of specialized hardware (~20× for
//! 2048-bit modular squaring per the design record). A deadline exactly at
//! the boundary FAILED in the executable model (S08) and fails here.

/// Strict horizon check.
pub fn deadline_ok(deadline_secs: f64, t_target_secs: f64, s_max: f64) -> bool {
    deadline_secs > 0.0 && s_max > 0.0 && deadline_secs < t_target_secs / (2.0 * s_max)
}

/// Size `T` (squaring count) so that a puzzle takes at least
/// `min_solve_secs` even on hardware `s_max`× faster than the calibrated
/// `squarings_per_sec`.
pub fn size_t(min_solve_secs: f64, squarings_per_sec: f64, s_max: f64) -> u64 {
    (min_solve_secs * squarings_per_sec * s_max).ceil() as u64
}

/// The latest safe claim deadline for a puzzle of `t` squarings on hardware
/// calibrated at `squarings_per_sec`, applying the strict rule.
pub fn max_deadline_secs(t: u64, squarings_per_sec: f64, s_max: f64) -> f64 {
    let t_target = t as f64 / squarings_per_sec;
    // Audit #19: return a value STRICTLY under the bound so it passes the
    // strict deadline_ok check (which the boundary value fails).
    let bound = t_target / (2.0 * s_max);
    bound - bound.abs() * f64::EPSILON.max(1e-9)
}
