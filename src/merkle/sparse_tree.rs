//! Sparse Merkle Tree (Depth 32)
//! Poseidon-based

use std::collections::HashMap;

use poseidon_rs::Fr;
use ff_ce::Field;

use crate::hash::poseidon::poseidon2;

const TREE_DEPTH: usize = 32;

pub struct SparseMerkleTree {
    nodes: HashMap<(usize, u64), Fr>,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    pub fn insert(&mut self, index: u64, value: Fr) -> Result<(), String> {
        let mut current_hash = value;
        let mut current_index = index;

        self.nodes.insert((0, current_index), current_hash);

        for level in 1..=TREE_DEPTH {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling_hash = self
                .nodes
                .get(&(level - 1, sibling_index))
                .cloned()
                .unwrap_or_else(Fr::zero);

            let (left, right) = if current_index % 2 == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            current_hash = poseidon2(left, right)?;

            current_index /= 2;
            self.nodes.insert((level, current_index), current_hash);
        }

        Ok(())
    }

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
    use ff_ce::{Field, PrimeField};

    #[test]
    fn test_insert_changes_root() {
        let mut tree = SparseMerkleTree::new();

        let leaf = Fr::from_str("123").unwrap();

        tree.insert(5, leaf).unwrap();

        let root = tree.root();

        assert!(!root.is_zero());
    }

    #[test]
    fn test_two_inserts_produce_different_root() {
        let mut tree = SparseMerkleTree::new();

        tree.insert(1, Fr::from_str("111").unwrap()).unwrap();
        let root1 = tree.root();

        tree.insert(2, Fr::from_str("222").unwrap()).unwrap();
        let root2 = tree.root();

        assert_ne!(root1, root2);
    }
}
