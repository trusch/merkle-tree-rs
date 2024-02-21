mod merkle_tree;

use merkle_tree::MerkleTree;

fn main() {

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
