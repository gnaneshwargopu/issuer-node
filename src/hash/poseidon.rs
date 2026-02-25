// src/hash/poseidon.rs

//! Poseidon hash wrapper for issuer protocol layer
//! MVP version
//! Compatible with poseidon-rs 0.0.8

use poseidon_rs::{Fr, Poseidon};

/// Computes Poseidon hash over BN254 field elements.
pub fn poseidon_hash(inputs: &[Fr]) -> Result<Fr, String> {
    let poseidon = Poseidon::new();
    poseidon.hash(inputs.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ce::{Field, PrimeField}; // <-- IMPORTANT

    #[test]
    fn test_poseidon_hash_runs() {
        let a = Fr::from_str("1").unwrap();
        let b = Fr::from_str("2").unwrap();

        let hash = poseidon_hash(&[a, b]).unwrap();

        assert!(!hash.is_zero());
    }

    #[test]
    fn test_poseidon_deterministic() {
        let a = Fr::from_str("10").unwrap();
        let b = Fr::from_str("20").unwrap();

        let h1 = poseidon_hash(&[a, b]).unwrap();
        let h2 = poseidon_hash(&[a, b]).unwrap();

        assert_eq!(h1, h2);
    }
}