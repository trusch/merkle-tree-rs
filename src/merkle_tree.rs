use std::fmt::Debug;

use sha3::{Digest, Sha3_256};

/// A simple Merkle tree implementation
pub struct MerkleTree {
    /// depth of the tree
    depth: usize,
    /// nodes of the tree in breadth-first traversal order
    nodes: Vec<[u8; 32]>,
}

impl MerkleTree {

    /// creates a new Merkle tree with the given depth and initial value for the leaves
    pub fn new(depth: usize, initial_value: &[u8; 32]) -> Self {
        // panic if depth < 1
        if depth < 1 {
            panic!("Merkle tree depth must be at least 1");
        }

        let mut nodes = vec![initial_value.to_owned(); Self::nodes_in_tree(depth)];
        
        // update all the hashes of the intermediate layers. Note that all hashes within one layer are the same
        for d in (0..depth - 1).rev() {
            // compute hash of (d, 0)
            let mut hasher = Sha3_256::new();
            hasher.update(&nodes[Self::first_child_index(d, 0)]);
            hasher.update(&nodes[Self::second_child_index(d, 0)]);
            let hash = hasher.finalize();
            // set all nodes in the layer to the same hash
            for i in 0..(1 << d) {
                nodes[Self::index(d, i)] = hash.into();
            }
        }
        Self { depth, nodes }
    }

    /// returns the root hash of the tree
    pub fn root_hash(&self) -> &[u8; 32] {
        &self.nodes[0]
    }

    /// returns the number of leaves in the tree
    pub fn num_leaves(&self) -> usize {
        1 << (self.depth - 1)
    }

    /// updates the value of a leaf node
    pub fn set(&mut self, offset: usize, value: &[u8; 32]) {
        // find index of the node to update and set the new value
        let index = Self::index(self.depth - 1, offset);
        self.nodes[index] = value.to_owned();

        // update all parent nodes
        // start from the parent of the updated node and go up to the root
        let (mut parent_layer, mut parent_offset) =
            Self::depth_offset(Self::parent_index(self.depth - 1, offset));
        loop {
            // compute new hash
            let mut hasher = Sha3_256::new();
            hasher.update(&self.nodes[Self::first_child_index(parent_layer, parent_offset)]);
            hasher.update(&self.nodes[Self::second_child_index(parent_layer, parent_offset)]);
            let hash = hasher.finalize();

            // set the new hash
            self.nodes[Self::index(parent_layer, parent_offset)] = hash.into();

            // check if we reached the root
            if parent_layer == 0 {
                break;
            }

            // move to the parent of the current node
            parent_offset = parent_offset / 2;
            parent_layer -= 1;
        }
    }

    /// Create a proof for a leaf node
    /// The proof is a list of hashes that can be used to verify the inclusion of the leaf in the tree
    /// Returns a list of (hash, is_left) pairs, where hash is the hash of the sibling of the node on the path to the root
    pub fn create_proof(&self, offset: usize) -> Vec<([u8; 32], bool)> {
        let mut proof = Vec::new();
        let mut current_offset = offset;
        let mut current_layer = self.depth - 1;
        while current_layer > 0 {
            let sibling_offset = if current_offset % 2 == 0 {
                current_offset + 1
            } else {
                current_offset - 1
            };
            let sibling_index = Self::index(current_layer, sibling_offset);
            let sibling_hash = self.nodes[sibling_index];
            proof.push((sibling_hash, current_offset % 2 == 0));
            current_offset /= 2;
            current_layer -= 1;
        }
        proof
    }

    /// Verify a proof for a leaf node
    /// The proof is a list of hashes that can be used to verify the inclusion of the leaf in the tree
    pub fn verify_proof(&self, value: &[u8; 32], proof: &[([u8; 32], bool)]) -> [u8; 32] {
        let mut current_value = value.clone();
        for (hash, is_left) in proof {
            let mut hasher = Sha3_256::new();
            if *is_left {
                hasher.update(&current_value);
                hasher.update(hash);
            } else {
                hasher.update(hash);
                hasher.update(&current_value);
            }
            current_value = hasher.finalize().into();
        }
        current_value
    }

    /// returns the index of a node given its depth and offset
    /// depth is the level of the node in the tree
    /// offset is the position of the node in the level
    /// 
    fn index(depth: usize, offset: usize) -> usize {
        Self::nodes_in_tree(depth) + offset
    }

    /// returns the index of the parent of a node
    fn parent_index(depth: usize, offset: usize) -> usize {
        Self::index(depth - 1, offset / 2)
    }

    /// returns the index of the first child of a node
    fn first_child_index(depth: usize, offset: usize) -> usize {
        Self::index(depth + 1, offset * 2)
    }

    /// returns the index of the second child of a node
    fn second_child_index(depth: usize, offset: usize) -> usize {
        Self::index(depth + 1, offset * 2 + 1)
    }

    /// returns (depth, offset) of a node given its index
    fn depth_offset(index: usize) -> (usize, usize) {
        let depth = Self::log2(index + 1);
        let offset = index - Self::nodes_in_tree(depth);
        (depth, offset)
    }

    /// returns the number of nodes in a tree of the given depth
    /// returns 2^depth - 1
    fn nodes_in_tree(depth: usize) -> usize {
        (1 << depth) - 1
    }

    /// returns log2 of the given number by checking leading zeroes ignoring the rest
    fn log2(x: usize) -> usize {
        if x == 0 {
            return 0;
        }
        usize::BITS as usize - x.leading_zeros() as usize - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log2() {
        assert_eq!(MerkleTree::log2(0), 0);
        assert_eq!(MerkleTree::log2(1), 0);
        assert_eq!(MerkleTree::log2(2), 1);
        assert_eq!(MerkleTree::log2(3), 1);
        assert_eq!(MerkleTree::log2(4), 2);
        assert_eq!(MerkleTree::log2(5), 2);
        assert_eq!(MerkleTree::log2(6), 2);
        assert_eq!(MerkleTree::log2(7), 2);
        assert_eq!(MerkleTree::log2(8), 3);
    }

    #[test]
    fn test_nodes_in_tree() {
        assert_eq!(MerkleTree::nodes_in_tree(0), 0);
        assert_eq!(MerkleTree::nodes_in_tree(1), 1);
        assert_eq!(MerkleTree::nodes_in_tree(2), 3);
        assert_eq!(MerkleTree::nodes_in_tree(3), 7);
    }

    #[test]
    fn test_num_leaves() {
        let tree = MerkleTree::new(1, &[0u8; 32]);
        assert_eq!(tree.num_leaves(), 1);
        let tree = MerkleTree::new(2, &[0u8; 32]);
        assert_eq!(tree.num_leaves(), 2);
        let tree = MerkleTree::new(3, &[0u8; 32]);
        assert_eq!(tree.num_leaves(), 4);
        let tree = MerkleTree::new(4, &[0u8; 32]);
        assert_eq!(tree.num_leaves(), 8);
    }

    #[test]
    fn test_index() {
        assert_eq!(MerkleTree::index(0, 0), 0);
        assert_eq!(MerkleTree::index(1, 0), 1);
        assert_eq!(MerkleTree::index(1, 1), 2);
        assert_eq!(MerkleTree::index(2, 0), 3);
        assert_eq!(MerkleTree::index(2, 1), 4);
        assert_eq!(MerkleTree::index(2, 2), 5);
        assert_eq!(MerkleTree::index(2, 3), 6);
    }

    #[test]
    fn test_parent_index() {
        assert_eq!(MerkleTree::parent_index(1, 0), 0);
        assert_eq!(MerkleTree::parent_index(1, 1), 0);
        assert_eq!(MerkleTree::parent_index(2, 0), 1);
        assert_eq!(MerkleTree::parent_index(2, 1), 1);
        assert_eq!(MerkleTree::parent_index(2, 2), 2);
        assert_eq!(MerkleTree::parent_index(2, 3), 2);
        assert_eq!(MerkleTree::parent_index(3, 0), 3);
        assert_eq!(MerkleTree::parent_index(3, 1), 3);
        assert_eq!(MerkleTree::parent_index(3, 2), 4);
        assert_eq!(MerkleTree::parent_index(3, 3), 4);
    }

    #[test]
    fn test_first_child_index() {
        assert_eq!(MerkleTree::first_child_index(0, 0), 1);
        assert_eq!(MerkleTree::first_child_index(1, 0), 3);
        assert_eq!(MerkleTree::first_child_index(1, 1), 5);
        assert_eq!(MerkleTree::first_child_index(2, 0), 7);
        assert_eq!(MerkleTree::first_child_index(2, 1), 9);
    }

    #[test]
    fn test_second_child_index() {
        assert_eq!(MerkleTree::second_child_index(0, 0), 2);
        assert_eq!(MerkleTree::second_child_index(1, 0), 4);
        assert_eq!(MerkleTree::second_child_index(1, 1), 6);
        assert_eq!(MerkleTree::second_child_index(2, 0), 8);
        assert_eq!(MerkleTree::second_child_index(2, 1), 10);
    }

    #[test]
    fn test_merkle_tree() {
        let initial_value = [0u8; 32];
        let tree = MerkleTree::new(3, &initial_value);

        // check leaves
        assert_eq!(tree.nodes[3], initial_value);
        assert_eq!(tree.nodes[4], initial_value);
        assert_eq!(tree.nodes[5], initial_value);
        assert_eq!(tree.nodes[6], initial_value);

        // check layer 2
        let mut hasher = Sha3_256::new();
        hasher.update(&initial_value);
        hasher.update(&initial_value);
        let hash = hasher.finalize();
        assert_eq!(tree.nodes[1], hash.as_slice());
        assert_eq!(tree.nodes[2], hash.as_slice());

        // check root
        let mut hasher = Sha3_256::new();
        hasher.update(&hash);
        hasher.update(&hash);
        let root = hasher.finalize();
        assert_eq!(tree.nodes[0], root.as_slice());
    }

    #[test]
    fn test_set() {
        let initial_value = [0u8; 32];
        let mut tree = MerkleTree::new(3, &initial_value);

        let new_value = [1u8; 32];
        tree.set(0, &new_value);

        // check leaves
        assert_eq!(tree.nodes[3], new_value);
        assert_eq!(tree.nodes[4], initial_value);
        assert_eq!(tree.nodes[5], initial_value);
        assert_eq!(tree.nodes[6], initial_value);

        // check layer 2
        let mut hasher = Sha3_256::new();
        hasher.update(&new_value);
        hasher.update(&initial_value);
        let hash_index_1 = hasher.finalize();
        assert_eq!(tree.nodes[1], hash_index_1.as_slice());

        let mut hasher = Sha3_256::new();
        hasher.update(&initial_value);
        hasher.update(&initial_value);
        let hash_index_2 = hasher.finalize();
        assert_eq!(tree.nodes[2], hash_index_2.as_slice());

        // check root
        let mut hasher = Sha3_256::new();
        hasher.update(&hash_index_1);
        hasher.update(&hash_index_2);
        let root = hasher.finalize();
        assert_eq!(tree.nodes[0], root.as_slice());
    }

    #[test]
    fn test_set_with_demo_values_from_exercise() {
        // From the exercise:
        // initial_leaf = 0x0000000000000000000000000000000000000000000000000000000000000000
        // tree = MerkleTree::new(depth = 5, initial_leaf = initial_leaf)
        // for i in 0..tree.num_leaves():
        //   tree.set(i, i * 0x1111111111111111111111111111111111111111111111111111111111111111)
        // assert tree.root() == 0x57054e43fa56333fd51343b09460d48b9204999c376624f52480c5593b91eff4
        let initial_value = [0x00; 32];
        let mut tree = MerkleTree::new(5, &initial_value);
        for i in 0..tree.num_leaves() {
            let updated_value = [(i * 0x11) as u8; 32];
            tree.set(i, &updated_value);
        }
        assert_eq!(
            tree.root_hash(),
            hex::decode("57054e43fa56333fd51343b09460d48b9204999c376624f52480c5593b91eff4")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_init_with_demo_values_from_exercise() {
        // From the exercise:
        // initial_leaf = 0xabababababababababababababababababababababababababababababababab
        // tree = MerkleTree::new(depth = 20, initial_leaf = initial_leaf)
        // assert tree.root() == 0xd4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930
        let initial_value =
            hex::decode("abababababababababababababababababababababababababababababababab")
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap();
        let tree = MerkleTree::new(20, &initial_value);
        assert_eq!(
            tree.root_hash(),
            hex::decode("d4490f4d374ca8a44685fe9471c5b8dbe58cdffd13d30d9aba15dd29efb92930")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_create_proof_with_demo_values_from_exercise() {
        // From the exercise:
        // initial_leaf = 0x0000000000000000000000000000000000000000000000000000000000000000
        // tree = MerkleTree::new(depth = 5, initial_leaf = initial_leaf)
        // for i in 0..tree.num_leaves():
        // tree.set(i, i * 0x1111111111111111111111111111111111111111111111111111111111111111)
        // assert tree.root() == 0x57054e43fa56333fd51343b09460d48b9204999c376624f52480c5593b91eff4
        // assert tree.proof(3) == [
        // right, sibling = 0x2222222222222222222222222222222222222222222222222222222222222222
        // right, sibling = 0x35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10
        // left, sibling = 0x26fca7737f48fa702664c8b468e34c858e62f51762386bd0bddaa7050e0dd7c0
        // left, sibling = 0xe7e11a86a0c1d8d8624b1629cb58e39bb4d0364cb8cb33c4029662ab30336858
        // ]
        let initial_value = [0x00; 32];
        let mut tree = MerkleTree::new(5, &initial_value);
        for i in 0..tree.num_leaves() {
            let updated_value = [(i * 0x11) as u8; 32];
            tree.set(i, &updated_value);
        }
        let proof = tree.create_proof(3);
        assert_eq!(
            proof,
            vec![
                (
                    hex::decode("2222222222222222222222222222222222222222222222222222222222222222")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    false
                ),
                (
                    hex::decode("35e794f1b42c224a8e390ce37e141a8d74aa53e151c1d1b9a03f88c65adb9e10")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    false
                ),
                (
                    hex::decode("26fca7737f48fa702664c8b468e34c858e62f51762386bd0bddaa7050e0dd7c0")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    true
                ),
                (
                    hex::decode("e7e11a86a0c1d8d8624b1629cb58e39bb4d0364cb8cb33c4029662ab30336858")
                        .unwrap()
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    true
                ),
            ]);
    }

    #[test]
    fn test_verify_proof_with_demo_values_from_exercise() {
        // From the exercise:
        // initial_leaf = 0x0000000000000000000000000000000000000000000000000000000000000000
        // tree = MerkleTree::new(depth = 5, initial_leaf = initial_leaf)
        // for i in 0..tree.num_leaves():
        // tree.set(i, i * 0x1111111111111111111111111111111111111111111111111111111111111111)
        // leaf_5 = 5 * 0x1111111111111111111111111111111111111111111111111111111111111111
        // root = tree.root()
        // proof = tree.proof(3)
        // assert verify(proof, leaf_5) == root
        let initial_value = [0x00; 32];
        let mut tree = MerkleTree::new(5, &initial_value);
        for i in 0..tree.num_leaves() {
            let updated_value = [(i * 0x11) as u8; 32];
            tree.set(i, &updated_value);
        }
        let leaf_5 = [5 * 0x11 as u8; 32];
        let root = tree.root_hash();
        let proof = tree.create_proof(5);
        assert_eq!(&tree.verify_proof(&leaf_5, &proof), root);

    }

}
