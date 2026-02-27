//! Poseidon hash wrapper
//! BN254 compatible
//! Used for SMT + identity state

use poseidon_rs::{Fr, Poseidon};

/// Hash 2 field elements (SMT internal nodes)
pub fn poseidon2(left: Fr, right: Fr) -> Result<Fr, String> {
    let p = Poseidon::new();
    p.hash(vec![left, right])
        .map_err(|e| format!("Poseidon error: {e:?}"))
}

/// Hash 3 field elements (Identity state)
pub fn poseidon3(a: Fr, b: Fr, c: Fr) -> Result<Fr, String> {
    let p = Poseidon::new();
    p.hash(vec![a, b, c])
        .map_err(|e| format!("Poseidon error: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ce::{Field, PrimeField};

    #[test]
    fn test_poseidon2_deterministic() {
        let a = Fr::from_str("10").unwrap();
        let b = Fr::from_str("20").unwrap();

        let h1 = poseidon2(a, b).unwrap();
        let h2 = poseidon2(a, b).unwrap();

        assert_eq!(h1, h2);
        assert!(!h1.is_zero());
    }

    #[test]
    fn test_poseidon3_deterministic() {
        let a = Fr::from_str("1").unwrap();
        let b = Fr::from_str("2").unwrap();
        let c = Fr::from_str("3").unwrap();

        let h1 = poseidon3(a, b, c).unwrap();
        let h2 = poseidon3(a, b, c).unwrap();

        assert_eq!(h1, h2);
    }
}
