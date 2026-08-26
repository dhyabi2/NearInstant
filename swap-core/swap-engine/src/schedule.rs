//! I1 chunk schedules.
//!
//! A swap of `total` raw units is split into chunks so that an abort at any
//! point strands at most one chunk of value in flight. Chunk size adapts
//! between bounds: small enough to bound risk, large enough that per-chunk
//! overhead (PoW, ceremonies) stays negligible.

/// A chunk schedule for one swap session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Schedule {
    /// Chunk values in raw units; sums exactly to the swap total.
    pub chunks: Vec<u128>,
}

/// Errors building a schedule.
#[derive(Debug, PartialEq, Eq)]
pub enum ScheduleError {
    ZeroTotal,
    /// `max_chunk` is zero or below `min_chunk`.
    BadBounds,
    /// The chunk count would exceed `max_chunks` even at `max_chunk` size.
    TooManyChunks,
}

impl Schedule {
    /// Build a schedule: as many `max_chunk`-sized chunks as needed, with the
    /// remainder folded into the final chunk when it would fall below
    /// `min_chunk` (a dust tail is worse than a slightly larger last chunk —
    /// but the fold is capped so no chunk ever exceeds `max_chunk + min_chunk`).
    pub fn build(
        total: u128,
        min_chunk: u128,
        max_chunk: u128,
        max_chunks: usize,
    ) -> Result<Self, ScheduleError> {
        if total == 0 {
            return Err(ScheduleError::ZeroTotal);
        }
        if max_chunk == 0 || min_chunk > max_chunk {
            return Err(ScheduleError::BadBounds);
        }
        let mut chunks = Vec::new();
        let mut remaining = total;
        while remaining > 0 {
            if chunks.len() >= max_chunks {
                return Err(ScheduleError::TooManyChunks);
            }
            if remaining <= max_chunk {
                chunks.push(remaining);
                remaining = 0;
            } else if remaining - max_chunk < min_chunk {
                // Audit #14: the tail is below min_chunk but folding it into one
                // chunk would exceed max_chunk (the operator's per-abort risk
                // cap). Split into two balanced chunks instead, each ≤ max_chunk.
                // Audit (schedule off-by-one): this branch pushes TWO chunks, so
                // the single len>=max_chunks guard at the loop top can be one
                // short — re-check there is room for both before splitting.
                if chunks.len() + 2 > max_chunks {
                    return Err(ScheduleError::TooManyChunks);
                }
                let half = remaining / 2;
                chunks.push(half);
                chunks.push(remaining - half);
                remaining = 0;
            } else {
                chunks.push(max_chunk);
                remaining -= max_chunk;
            }
        }
        Ok(Schedule { chunks })
    }

    pub fn total(&self) -> u128 {
        self.chunks.iter().sum()
    }

    /// The worst-case value in flight — the I1 loss bound: the largest chunk.
    pub fn max_at_risk(&self) -> u128 {
        self.chunks.iter().copied().max().unwrap_or(0)
    }
}
