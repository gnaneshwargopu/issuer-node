// src/merkle/sparse_tree.rs

//! Sparse Merkle Tree (Depth 32)
//! MVP in-memory implementation
//! Hash function: Poseidon

use std::collections::HashMap;

use poseidon_rs::Fr;
use ff_ce::{Field, PrimeField};

use crate::hash::poseidon::poseidon_hash;

const TREE_DEPTH: usize = 32;

/// Sparse Merkle Tree structure
pub struct SparseMerkleTree {
    // Node storage: (level, index) -> hash
    nodes: HashMap<(usize, u64), Fr>,
}

impl SparseMerkleTree {
    /// Create new empty tree
    pub fn new() -> Self {
        SparseMerkleTree {
            nodes: HashMap::new(),
        }
    }
        /// Generate inclusion proof for given index
    pub fn generate_proof(&self, index: u64) -> Vec<Fr> {
        let mut proof = Vec::with_capacity(TREE_DEPTH);

        let mut current_index = index;

        for level in 0..TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling_hash = self
                .nodes
                .get(&(level, sibling_index))
                .cloned()
                .unwrap_or_else(Fr::zero);

            proof.push(sibling_hash);

            current_index /= 2;
        }

        proof
    }
        /// Verify inclusion proof
    pub fn verify_proof(
        leaf: Fr,
        index: u64,
        proof: &[Fr],
        expected_root: Fr,
    ) -> Result<bool, String> {
        let mut current_hash = leaf;
        let mut current_index = index;

        for sibling_hash in proof {
            let (left, right) = if current_index % 2 == 0 {
                (current_hash, *sibling_hash)
            } else {
                (*sibling_hash, current_hash)
            };

            current_hash = poseidon_hash(&[left, right])?;
            current_index /= 2;
        }

        Ok(current_hash == expected_root)
    }
    /// Insert leaf at given index
    pub fn insert(&mut self, index: u64, value: Fr) -> Result<(), String> {
        let mut current_hash = value;
        let mut current_index = index;

        // Insert leaf at level 0
        self.nodes.insert((0, current_index), current_hash);

        for level in 1..=TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let left;
            let right;

            if current_index % 2 == 0 {
                left = current_hash;
                right = self
                    .nodes
                    .get(&(level - 1, sibling_index))
                    .cloned()
                    .unwrap_or_else(Fr::zero);
            } else {
                left = self
                    .nodes
                    .get(&(level - 1, sibling_index))
                    .cloned()
                    .unwrap_or_else(Fr::zero);
                right = current_hash;
            }

            current_hash = poseidon_hash(&[left, right])?;

            current_index /= 2;
            self.nodes.insert((level, current_index), current_hash);
        }

        Ok(())
    }

    /// Get current root
    pub fn root(&self) -> Fr {
        self.nodes
            .get(&(TREE_DEPTH, 0))
            .cloned()
            .unwrap_or_else(Fr::zero)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smt_insert() {
        let mut tree = SparseMerkleTree::new();

        let leaf = Fr::from_str("123").unwrap();

        tree.insert(5, leaf).unwrap();

        let root = tree.root();

        assert!(!root.is_zero());
    }
        #[test]
    fn test_smt_proof_verification() {
        let mut tree = SparseMerkleTree::new();

        let leaf = Fr::from_str("999").unwrap();

        tree.insert(7, leaf).unwrap();

        let root = tree.root();

        let proof = tree.generate_proof(7);

        let is_valid = SparseMerkleTree::verify_proof(
            leaf,
            7,
            &proof,
            root,
        )
        .unwrap();

        assert!(is_valid);
    }
}