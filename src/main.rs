mod merkle_tree;

use merkle_tree::MerkleTree;
use sha3::Sha3_256;

fn main() {
    let initial_value = [0x00; 32];
    let mut tree = MerkleTree::<Sha3_256>::new(5, &initial_value.into());
    for i in 0..tree.num_leaves() {
        let updated_value = [(i * 0x11) as u8; 32];
        tree.set(i, &updated_value.into());
    }
    let leaf_5 = [5 * 0x11_u8; 32].into();
    let root = tree.root_hash();
    let proof = tree.create_proof(5);
    assert_eq!(&tree.verify_proof(&leaf_5, &proof), root);
}
