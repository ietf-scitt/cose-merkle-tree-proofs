import cbor2
import pycose.keys
from pycose.messages import Sign1Message

import merkle_proofs.tree_algorithms as ta

COSE_TREE_ALG_LABEL = "treealg"
COSE_TREE_SIZE_LABEL = "treesize"

def sign_tree_root(root: bytes, tree_alg: ta.TreeAlgorithm, key, alg, tree_size=None, detached=False) -> bytes:
    phdr = {}
    phdr[pycose.headers.Algorithm] = alg
    phdr[COSE_TREE_ALG_LABEL] = tree_alg.IDENTIFIER
    if tree_size is not None:
        if not isinstance(tree_size, int):
            raise TypeError("tree_size must be an integer")
        phdr[COSE_TREE_SIZE_LABEL] = tree_size
    
    msg = Sign1Message(phdr=phdr, payload=root)
    msg.key = key
    signed = msg.encode(tag=True)
    if not detached:
        return signed
    detached = detach_cose_sign1_payload(signed)
    return detached


def detach_cose_sign1_payload(msg):
    # pycose doesn't support detached payloads, so we have to do it manually.
    decoded = cbor2.loads(msg)
    assert decoded.tag == Sign1Message.cbor_tag
    [phdr, uhdr, _, signature] = decoded.value

    detached = cbor2.CBORTag(Sign1Message.cbor_tag, [
        phdr,
        uhdr,
        None,
        signature,
    ])
    return cbor2.dumps(detached)
