//! iden3 Identity Engine (Pure 3-SMT model)

use poseidon_rs::Fr;
use ff_ce::Field;

use crate::claims::claim::Claim;
use crate::merkle::sparse_tree::SparseMerkleTree;
use crate::hash::poseidon::poseidon3;
use crate::db::postgres::Db;

pub struct Issuer {
    pub claims_tree: SparseMerkleTree,
    pub revocation_tree: SparseMerkleTree,
    pub roots_tree: SparseMerkleTree,
    pub db: Db,
}

impl Issuer {
    pub async fn new() -> Result<Self, String> {
        let db = Db::new().await?;
        let claims = db.load_claims().await?;

        let mut claims_tree = SparseMerkleTree::new();

        for (pos, commitment) in claims {
            claims_tree.insert(pos, commitment)?;
        }

        Ok(Self {
            claims_tree,
            revocation_tree: SparseMerkleTree::new(),
            roots_tree: SparseMerkleTree::new(),
            db,
        })
    }

    pub fn compute_state(&self) -> Result<Fr, String> {
        let claims_root = self.claims_tree.root();
        let revocation_root = self.revocation_tree.root();
        let roots_root = self.roots_tree.root();

        poseidon3(claims_root, revocation_root, roots_root)
    }

    pub async fn issue_claim(
        &mut self,
        index: u64,
        claim: Claim,
    ) -> Result<Fr, String> {

        let commitment = claim.commitment()?;

        // 1️⃣ Insert claim
        self.claims_tree.insert(index, commitment)?;

        // 2️⃣ Get new Claims Root
        let claims_root = self.claims_tree.root();

        // 3️⃣ Insert ClaimsRoot into Roots Tree
        self.roots_tree.insert(index, claims_root)?;

        let revocation_root = self.revocation_tree.root();

        // 4️⃣ Compute full Identity State
        let state = self.compute_state()?;

        // 5️⃣ Persist
        self.db.save_claim(index, &commitment).await?;
        self.db.save_state(&state, &claims_root, &revocation_root).await?;

        Ok(state)
    }

    pub async fn revoke_claim(
        &mut self,
        rev_nonce: u64,
    ) -> Result<Fr, String> {

        let flag = Fr::one();
        self.revocation_tree.insert(rev_nonce, flag)?;

        let state = self.compute_state()?;

        self.db
            .save_state(
                &state,
                &self.claims_tree.root(),
                &self.revocation_tree.root(),
            )
            .await?;

        Ok(state)
    }
}

/// Convert Fr to tree position
fn fr_to_u64(fr: Fr) -> u64 {
    use ff_ce::PrimeField;
    let repr = fr.into_repr();
    repr.as_ref()[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff_ce::{Field, PrimeField};

    #[tokio::test]
    async fn test_issue_updates_claims_tree() {
        let mut issuer = Issuer::new().await.unwrap();

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

        let state = issuer.issue_claim(0, claim).await.unwrap();

        assert!(!state.is_zero());
        assert!(!issuer.claims_tree.root().is_zero());
    }

    #[tokio::test]
    async fn test_revoke_updates_revocation_tree() {
        let mut issuer = Issuer::new().await.unwrap();

        let state = issuer.revoke_claim(5).await.unwrap();

        assert!(!state.is_zero());
        assert!(!issuer.revocation_tree.root().is_zero());
    }

    #[tokio::test]
    async fn test_identity_state_changes_after_issue() {
        let mut issuer = Issuer::new().await.unwrap();

        let initial_state = issuer.compute_state().unwrap();

        let claim = Claim::new(
            Fr::from_str("11").unwrap(),
            Fr::from_str("22").unwrap(),
            Fr::from_str("33").unwrap(),
            Fr::from_str("0").unwrap(),
            [
                Fr::from_str("44").unwrap(),
                Fr::from_str("55").unwrap(),
                Fr::from_str("66").unwrap(),
                Fr::from_str("77").unwrap(),
            ],
        );

        let new_state = issuer.issue_claim(1, claim).await.unwrap();

        assert_ne!(initial_state, new_state);
    }
}
