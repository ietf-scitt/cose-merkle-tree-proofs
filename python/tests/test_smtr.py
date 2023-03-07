import pytest
import pycose.keys
import pycose.algorithms
from pycose.messages import Sign1Message

import merkle_proofs.tree_algorithms as ta
from merkle_proofs import smtr


def test_smtr_encoding_with_tree_size():
    tree_alg = ta.RFC6962Sha256TreeAlgorithm()
    entries = [ta.Entry(f'entry_{i}'.encode(), None) for i in range(6)]
    entry_hashes = [tree_alg.hash_entry(e) for e in entries]
    root = tree_alg.compute_root_from_hashed_entries(entry_hashes)
    
    key = pycose.keys.EC2Key.generate_key('P_256')

    cose_msg = smtr.sign_tree_root(root, tree_alg, key, "ES256", tree_size=len(entries))

    decoded = Sign1Message.decode(cose_msg)
    assert decoded.payload == root
    assert decoded.phdr[pycose.headers.Algorithm] == pycose.algorithms.Es256
    assert decoded.phdr[smtr.COSE_TREE_ALG_LABEL] == tree_alg.IDENTIFIER
    assert decoded.phdr[smtr.COSE_TREE_SIZE_LABEL] == len(entries)


def test_smtr_encoding_without_tree_size():
    tree_alg = ta.OpenZeppelinKeccak256TreeAlgorithm()
    entries = [ta.Entry(f'entry_{i}'.encode(), None) for i in range(6)]
    entry_hashes = [tree_alg.hash_entry(e) for e in entries]
    root = tree_alg.compute_root_from_hashed_entries(entry_hashes)
    
    key = pycose.keys.EC2Key.generate_key('P_256')

    cose_msg = smtr.sign_tree_root(root, tree_alg, key, "ES256")

    decoded = Sign1Message.decode(cose_msg)
    assert decoded.payload == root
    assert decoded.phdr[pycose.headers.Algorithm] == pycose.algorithms.Es256
    assert decoded.phdr[smtr.COSE_TREE_ALG_LABEL] == tree_alg.IDENTIFIER
    assert smtr.COSE_TREE_SIZE_LABEL not in decoded.phdr
