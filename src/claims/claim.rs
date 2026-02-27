//! iden3 8-slot Claim
//! 4 index slots + 4 value slots

use poseidon_rs::Fr;
use crate::hash::poseidon::poseidon2;

pub struct Claim {
    pub index: [Fr; 4],
    pub value: [Fr; 4],
}

impl Claim {
    pub fn new(
        schema_hash: Fr,
        subject: Fr,
        rev_nonce: Fr,
        flags: Fr,
        values: [Fr; 4],
    ) -> Self {
        Self {
            index: [schema_hash, subject, rev_nonce, flags],
            value: values,
        }
    }

    /// Hash index side (used as SMT position)
    pub fn index_hash(&self) -> Result<Fr, String> {
        let h0 = poseidon2(self.index[0], self.index[1])?;
        let h1 = poseidon2(self.index[2], self.index[3])?;
        poseidon2(h0, h1)
    }

    /// Hash value side (used as SMT leaf value)
    pub fn value_hash(&self) -> Result<Fr, String> {
        let h0 = poseidon2(self.value[0], self.value[1])?;
        let h1 = poseidon2(self.value[2], self.value[3])?;
        poseidon2(h0, h1)
    }

    /// Commitment for SMT leaf
    pub fn commitment(&self) -> Result<Fr, String> {
        let index_hash = self.index_hash()?;
        let value_hash = self.value_hash()?;
        poseidon2(index_hash, value_hash)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ff_ce::{Field, PrimeField};

    #[test]
    fn test_index_hash_non_zero() {
        let claim = Claim::new(
            Fr::from_str("1").unwrap(),
            Fr::from_str("2").unwrap(),
            Fr::from_str("3").unwrap(),
            Fr::from_str("0").unwrap(),
            [
                Fr::from_str("10").unwrap(),
                Fr::from_str("20").unwrap(),
                Fr::from_str("30").unwrap(),
                Fr::from_str("40").unwrap(),
            ],
        );

        let index_hash = claim.index_hash().unwrap();
        assert!(!index_hash.is_zero());
    }

    #[test]
    fn test_value_hash_non_zero() {
        let claim = Claim::new(
            Fr::from_str("1").unwrap(),
            Fr::from_str("2").unwrap(),
            Fr::from_str("3").unwrap(),
            Fr::from_str("0").unwrap(),
            [
                Fr::from_str("10").unwrap(),
                Fr::from_str("20").unwrap(),
                Fr::from_str("30").unwrap(),
                Fr::from_str("40").unwrap(),
            ],
        );

        let value_hash = claim.value_hash().unwrap();
        assert!(!value_hash.is_zero());
    }
}
