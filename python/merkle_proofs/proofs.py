import cbor2

import merkle_proofs.tree_algorithms as ta

def encode_proof(smtr: bytes, inclusion_path: bytes, entry: ta.Entry):
    detached_smtr = detach_cose_sign1_payload(smtr)
    proof = [
        detached_smtr,
        inclusion_path,
        entry.extra_data,
        entry.payload,
    ]
    return cbor2.dumps(proof)    


def detach_cose_sign1_payload(msg):
    # pycose doesn't support detached payloads, so we have to do it manually.
    decoded = cbor2.loads(msg)
    assert decoded.tag == 18 # COSE_Sign1
    [phdr, uhdr, _, signature] = decoded.value

    detached = cbor2.CBORTag(18, [
        phdr,
        uhdr,
        None,
        signature,
    ])
    return cbor2.dumps(detached)
