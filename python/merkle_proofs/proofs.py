from typing import Optional
from dataclasses import dataclass
import cbor2

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

