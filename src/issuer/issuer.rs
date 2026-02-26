//! Issuer protocol core (MVP)
//! Supports:
//! - Claims Tree
//! - Revocation Tree
//! - Roots Tree

use poseidon_rs::Fr;
use ff_ce::PrimeField;
use crate::claims::claim::Claim;
use crate::merkle::sparse_tree::SparseMerkleTree;
use crate::db::postgres::Db;

pub struct Issuer {
    pub claims_tree: SparseMerkleTree,
    pub revocation_tree: SparseMerkleTree,
    pub roots_tree: SparseMerkleTree,
    pub db: Db,
}

impl Issuer {
    pub fn new() -> Self {
        let mut db = Db::new();
        let mut claims_tree = SparseMerkleTree::new();

        for (id, commitment) in db.load_claims() {
            claims_tree.insert(id, commitment).unwrap();
        }

        Issuer {
            claims_tree,
            revocation_tree: SparseMerkleTree::new(),
            roots_tree: SparseMerkleTree::new(),
            db,
        }
    }

    pub fn compute_state(&self) -> Result<Fr, String> {
        let claims_root = self.claims_tree.root();
        let revocation_root = self.revocation_tree.root();

        crate::hash::poseidon::poseidon_hash(&[
            claims_root,
            revocation_root,
        ])
    }

    pub fn issue_claim(
        &mut self,
        index: u64,
        claim: Claim,
    ) -> Result<Fr, String> {
        let commitment = claim.commitment()?;

        self.db.save_claim(index, &claim, &commitment);

        self.claims_tree.insert(index, commitment)?;

        let claims_root = self.claims_tree.root();
        let revocation_root = self.revocation_tree.root();
        let state = self.compute_state()?;

        self.db
            .save_state(&state, &claims_root, &revocation_root);

        Ok(state)
    }

    pub fn revoke_claim(
        &mut self,
        index: u64,
    ) -> Result<Fr, String> {
        let flag = Fr::from_str("1").unwrap();

        self.revocation_tree.insert(index, flag)?;

        let claims_root = self.claims_tree.root();
        let revocation_root = self.revocation_tree.root();
        let state = self.compute_state()?;

        self.db
            .save_state(&state, &claims_root, &revocation_root);

        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ce::{Field, PrimeField};

    #[test]
    fn test_issue_claim_flow() {
        let mut issuer = Issuer::new();

        let schema = Fr::from_str("1").unwrap();
        let subject = Fr::from_str("2").unwrap();
        let value = Fr::from_str("3").unwrap();

        let nonce = Fr::from_str("1").unwrap();
let flags = Fr::from_str("0").unwrap();

let values = [
    Fr::from_str("10").unwrap(),
    Fr::from_str("20").unwrap(),
    Fr::from_str("30").unwrap(),
    Fr::from_str("40").unwrap(),
];

    let claim = Claim::new(schema, subject, nonce, flags, values);

        let root = issuer.issue_claim(0, claim).unwrap();

        assert!(!root.is_zero());
    }

    #[test]
    fn test_revoke_claim_flow() {
        let mut issuer = Issuer::new();

        let revoke_root = issuer.revoke_claim(5).unwrap();

        assert!(!revoke_root.is_zero());
    }
}