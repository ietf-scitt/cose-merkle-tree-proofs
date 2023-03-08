import cbor2
import pycose

import merkle_proofs.tree_algorithms as ta
from merkle_proofs.smtr import sign_tree_root
from merkle_proofs.proofs import SignedMerkleTreeProof

def test_signed_merkle_tree_proof_encoding():
    tree_alg = ta.RFC6962Sha256TreeAlgorithm()
    entries = [ta.Entry(f'entry_{i}'.encode(), None) for i in range(6)]
    entry_hashes = [tree_alg.hash_entry(e) for e in entries]
    root = tree_alg.compute_root_from_hashed_entries(entry_hashes)
    
    key = pycose.keys.EC2Key.generate_key('P_256')

    smtr = sign_tree_root(root, tree_alg, key, "ES256", tree_size=len(entries), detached=True)

    entry_idx = 0
    inclusion_path = tree_alg.generate_index_aware_inclusion_path(entry_hashes, entry_idx).encode()

    smtp = SignedMerkleTreeProof(
        smtr,
        inclusion_path,
        entries[entry_idx].extra_data,
        entries[entry_idx].payload).encode()

    decoded = SignedMerkleTreeProof.decode(smtp)
    assert decoded.smtr == smtr
    assert decoded.inclusion_path == inclusion_path
    assert decoded.extra_data == entries[entry_idx].extra_data
    assert decoded.payload == entries[entry_idx].payload
    