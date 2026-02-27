use poseidon_rs::Fr;
use crate::merkle::sparse_tree::SparseMerkleTree;

pub struct Identity {
    pub claims_tree: SparseMerkleTree,
    pub revocation_tree: SparseMerkleTree,
    pub roots_tree: SparseMerkleTree,
    pub state: Fr,
}

impl Identity {
    pub fn new(depth: usize) -> Self {
        let claims_tree = SparseMerkleTree::new(depth);
        let revocation_tree = SparseMerkleTree::new(depth);
        let roots_tree = SparseMerkleTree::new(depth);

        let zero = Fr::zero();

        let state = poseidon_hash([
            claims_tree.root(),
            revocation_tree.root(),
            roots_tree.root(),
        ]);

        Self {
            claims_tree,
            revocation_tree,
            roots_tree,
            state,
        }
    }

    fn update_state(&mut self) {
        self.state = poseidon_hash([
            self.claims_tree.root(),
            self.revocation_tree.root(),
            self.roots_tree.root(),
        ]);
    }
}