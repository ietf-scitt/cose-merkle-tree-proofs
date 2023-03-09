from typing import Optional
from dataclasses import dataclass
import cbor2
from pycose.messages import Sign1Message

from merkle_proofs.smtr import COSE_TREE_ALG_LABEL, COSE_TREE_SIZE_LABEL, attach_cose_sign1_payload
from merkle_proofs.tree_algorithms import TreeAlgorithm, InclusionPath, Entry

@dataclass
class SignedMerkleTreeProof:
    smtr: bytes
    inclusion_path: bytes
    extra_data: Optional[bytes]
    payload: bytes

    def encode(self):
        proof = [
            self.smtr,
            self.inclusion_path,
            self.extra_data,
            self.payload,
        ]
        return cbor2.dumps(proof)

    @classmethod
    def decode(cls, encoded_proof):
        proof = cbor2.loads(encoded_proof)
        return cls(*proof)

    def verify(self, key):
        # Temporary hack:
        smtr = Sign1Message.decode(attach_cose_sign1_payload(self.smtr, b"dummy"))
        # Can be replaced with the following once pycose supports detached payloads:       
        # smtr = Sign1Message.decode(self.smtr)
        inclusion_path = InclusionPath.decode(self.inclusion_path)
        entry = Entry(self.payload, self.extra_data)

        tree_alg = TreeAlgorithm.from_identifier(smtr.phdr[COSE_TREE_ALG_LABEL])
        tree_size = smtr.phdr.get(COSE_TREE_SIZE_LABEL)

        entry_hash = tree_alg.hash_entry(entry)
        root = tree_alg.compute_root_from_inclusion_path(inclusion_path, entry_hash, tree_size)

        # Temporary hack:
        smtr = Sign1Message.decode(attach_cose_sign1_payload(self.smtr, root))
        smtr.key = key
        return smtr.verify_signature()
        # Can be replaced with the following once pycose supports detached payloads:
        # smtr.key = key
        # return smtr.verify_signature(detached_payload=root)
