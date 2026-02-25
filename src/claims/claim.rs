//! Full 8-slot iden3-compatible Claim structure
//! Spec-aligned layout: 4 index slots + 4 value slots

use poseidon_rs::Fr;
use ff_ce::{Field, PrimeField};

use crate::hash::poseidon::poseidon_hash;

pub struct Claim {
    pub index: [Fr; 4],
    pub value: [Fr; 4],
}

impl Claim {
    /// Create new full claim
    pub fn new(
        schema_hash: Fr,
        subject: Fr,
        rev_nonce: Fr,
        flags: Fr,
        values: [Fr; 4],
    ) -> Self {
        Claim {
            index: [schema_hash, subject, rev_nonce, flags],
            value: values,
        }
    }

    /// Flatten into 8-slot array
    pub fn slots(&self) -> [Fr; 8] {
        [
            self.index[0],
            self.index[1],
            self.index[2],
            self.index[3],
            self.value[0],
            self.value[1],
            self.value[2],
            self.value[3],
        ]
    }

    /// Compute Poseidon commitment over all 8 slots
    pub fn commitment(&self) -> Result<Fr, String> {
        // ----- INDEX SIDE -----
        let h_i0 = poseidon_hash(&[self.index[0], self.index[1]])?;
        let h_i1 = poseidon_hash(&[self.index[2], self.index[3]])?;
        let index_hash = poseidon_hash(&[h_i0, h_i1])?;

        // ----- VALUE SIDE -----
        let h_v0 = poseidon_hash(&[self.value[0], self.value[1]])?;
        let h_v1 = poseidon_hash(&[self.value[2], self.value[3]])?;
        let value_hash = poseidon_hash(&[h_v0, h_v1])?;

        // ----- FINAL CLAIM HASH -----
        poseidon_hash(&[index_hash, value_hash])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_claim_commitment() {
        let schema = Fr::from_str("1").unwrap();
        let subject = Fr::from_str("2").unwrap();
        let nonce = Fr::from_str("3").unwrap();
        let flags = Fr::from_str("0").unwrap();

        let values = [
            Fr::from_str("10").unwrap(),
            Fr::from_str("20").unwrap(),
            Fr::from_str("30").unwrap(),
            Fr::from_str("40").unwrap(),
        ];

        let claim = Claim::new(schema, subject, nonce, flags, values);

        let commitment = claim.commitment().unwrap();

        assert!(!commitment.is_zero());
    }
}