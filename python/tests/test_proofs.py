import cbor2
import pycose

import merkle_proofs.tree_algorithms as ta
from merkle_proofs.smtr import sign_tree_root
from merkle_proofs.proofs import SignedMerkleTreeProof

def test_signed_merkle_tree_proof():
    tree_alg = ta.RFC6962Sha256TreeAlgorithm()
    entries = [ta.Entry(f'entry_{i}'.encode(), None) for i in range(6)]
    entry_hashes = [tree_alg.hash_entry(e) for e in entries]
    root = tree_alg.compute_root_from_hashed_entries(entry_hashes)
    
    key = pycose.keys.EC2Key.generate_key('P_256')

    smtr = sign_tree_root(root, tree_alg, key, "ES256", tree_size=len(entries), detached=True)

    entry_idx = 0
    inclusion_path = tree_alg.generate_index_aware_inclusion_path(entry_hashes, entry_idx).encode()

    tree_proof_msg = SignedMerkleTreeProof(
        smtr,
        inclusion_path,
        entries[entry_idx].extra_data,
        entries[entry_idx].payload).encode()

    tree_proof = SignedMerkleTreeProof.decode(tree_proof_msg)
    assert tree_proof.smtr == smtr
    assert tree_proof.inclusion_path == inclusion_path
    assert tree_proof.extra_data == entries[entry_idx].extra_data
    assert tree_proof.payload == entries[entry_idx].payload

    assert tree_proof.verify(key)
