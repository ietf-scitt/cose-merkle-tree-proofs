import pycose.keys
from pycose.messages import Sign1Message

import merkle_proofs.tree_algorithms as ta

COSE_TREE_ALG_LABEL = "treealg"
COSE_TREE_SIZE_LABEL = "treesize"

def sign_tree_root(root: bytes, tree_alg: ta.TreeAlgorithm, key, alg, tree_size=None) -> bytes:
    phdr = {}
    phdr[pycose.headers.Algorithm] = alg
    phdr[COSE_TREE_ALG_LABEL] = tree_alg.IDENTIFIER
    if tree_size is not None:
        if not isinstance(tree_size, int):
            raise TypeError("tree_size must be an integer")
        phdr[COSE_TREE_SIZE_LABEL] = tree_size
    
    msg = Sign1Message(phdr=phdr, payload=root)
    msg.key = key
    return msg.encode(tag=True)
