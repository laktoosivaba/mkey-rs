//! Injectable random source for the SSP layer.
//!
//! The SSP handshake needs one 16-byte random value (`RandomB`) per session.
//! Production code uses [`OsRandom`], which draws from the operating system
//! CSPRNG. Tests and fixture generation use [`FixedRandom`], which replays a
//! preset list of values so the whole exchange becomes deterministic.

/// Source of 16-byte random values used by the SSP handshake.
pub trait RandomSource {
    /// Produce the next 16 random bytes.
    fn random16(&mut self) -> [u8; 16];
}

/// Cryptographically secure random source backed by the OS CSPRNG.
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn random16(&mut self) -> [u8; 16] {
        let mut buf = [0u8; 16];
        getrandom::fill(&mut buf).expect("OS random number generator unavailable");
        buf
    }
}

/// Deterministic random source that replays a preset list of values.
///
/// Test tooling only. Panics when the list is exhausted so a test can never
/// silently fall back to a value it did not expect.
#[derive(Debug, Clone, Default)]
pub struct FixedRandom {
    values: Vec<[u8; 16]>,
    next: usize,
}

impl FixedRandom {
    /// Create a source that returns `values` in order.
    pub fn new(values: Vec<[u8; 16]>) -> Self {
        Self { values, next: 0 }
    }

    /// Create a source that returns a single value.
    pub fn single(value: [u8; 16]) -> Self {
        Self::new(vec![value])
    }

    /// Number of values already consumed.
    pub fn consumed(&self) -> usize {
        self.next
    }

    /// Values that have not been consumed yet.
    pub fn remaining(&self) -> &[[u8; 16]] {
        &self.values[self.next.min(self.values.len())..]
    }
}

impl RandomSource for FixedRandom {
    fn random16(&mut self) -> [u8; 16] {
        let value = *self
            .values
            .get(self.next)
            .expect("FixedRandom exhausted: more random values requested than provided");
        self.next += 1;
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_random_returns_values_in_order() {
        let mut rng = FixedRandom::new(vec![[1u8; 16], [2u8; 16]]);
        assert_eq!(rng.random16(), [1u8; 16]);
        assert_eq!(rng.random16(), [2u8; 16]);
        assert_eq!(rng.consumed(), 2);
        assert!(rng.remaining().is_empty());
    }

    #[test]
    #[should_panic(expected = "FixedRandom exhausted")]
    fn fixed_random_panics_when_exhausted() {
        let mut rng = FixedRandom::single([0u8; 16]);
        let _ = rng.random16();
        let _ = rng.random16();
    }

    #[test]
    fn os_random_produces_distinct_values() {
        let mut rng = OsRandom;
        let a = rng.random16();
        let b = rng.random16();
        assert_ne!(a, b, "OS RNG returned the same 16 bytes twice");
        assert_ne!(a, [0u8; 16]);
    }
}
