# Concise Encoding of Signed Merkle Tree Proofs

## Status

DRAFT

## Goals

- Define a format for a Merkle tree root signature with metadata.
- Define a format for an inclusion path.
- Define a format for the disclosure of a single leaf payload, aka signed Merkle tree proof.
- All formats should be as compact as possible.

## Terminology

### Merkle Tree

A Merkle tree is a tree where every leaf is labelled with the cryptographic hash of a sequence of bytes and every node that is not a leaf is labeled with the cryptographic hash of the labels of its child nodes.

### Merkle Tree Root

A Merkle tree root is the root node of a tree which represents the cryptographic hash that commits to all leaves in the tree.

### Merkle Tree Algorithm

A Merkle tree algorithm specifies how nodes in the tree must be hashed to compute the root node.

### Payload and Extra Data

A payload is data bound to in a Merkle tree leaf. The Merkle tree algorithm determines how a payload together with extra data is bound to a leaf. The simplest case is that the payload is the leaf itself without extra data.

### Inclusion Path

An inclusion path confirms that a value is a leaf of a Merkle tree known only by its root hash (and tree size, possibly).

### Signed Merkle Tree Proof

A signed Merkle tree proof is the combination of signed Merkle tree root hash, inclusion path, extra data, and payload.

## Data formats

### Signed Merkle Tree Root

A Merkle tree root is signed with COSE_Sign1.

```c
SMTR = COSE_Sign1_Tagged
```

Protected header parameters:

- alg (label: 1): REQUIRED. Signature algorithm. Value type: int / tstr.
- tree alg (label: TBD): REQUIRED. Merkle tree algorithm. Value type: int / tstr.
- tree size (label: TBD): OPTIONAL. Merkle tree size as the number of leaves. Value type: uint.

A COSE profile of this specification may add further header parameters, for example to identify the signer.

Payload: Merkle tree root hash bytes.

Note: The payload is just the raw Merkle tree root hash (and not some wrapper structure) so that it can be detached and easily re-computed from an inclusion path and leaf bytes. This allows to design other structures that force re-computation and prevent faulty implementations (forgetting to match a computed root with one embedded in a signature).

### Inclusion Path

If the tree size and leaf index is known, then a compact inclusion path variant can be used:

```c
IndexAwareInclusionPath = [
    leaf_index: int
    hashes: [+ bstr]
]
```

Otherwise, the direction for each path step must be included:

```c
IndexUnawareInclusionPath = [+ PathEntry]
PathEntry = [
    left: bool
    hash: bstr
]
```

```c
UndirectionalInclusionPath = [+ bstr]
```

```c
InclusionPath = IndexAwareInclusionPath / IndexUnawareInclusionPath / UndirectionalInclusionPath
```

Note: Including the tree size and leaf index may not be appropriate in certain privacy-focused applications as an attacker may be able to derive private information from them.

TODO: Should leaf index be part of inclusion path (IndexAwareInclusionPath) or outside?

TODO: How are the two types of inclusion paths distinguished?

TODO: Define root computation algorithm for each inclusion path type

TODO: [Do we need both inclusion path types? what properties does each type have?](https://github.com/ietf-scitt/cose-merkle-tree-proofs/issues/6)

TODO: Should the inclusion path be opaque (bstr) and fixed by the tree algorithm? It seems this is orthogonal and the choice of inclusion path type should be application-specific.

### Signed Merkle Tree Proof

A signed Merkle tree proof is a CBOR array containing a signed tree root, an inclusion path, extra data for the tree algorithm, and the payload.

```c
SignedMerkleTreeProof = [
  signed_tree_root: COSE_Sign1_Tagged (detached)
  inclusion_path: InclusionPath
  extra_data: bstr / nil
  payload: bstr
]
```

`extra_data` is an additional input to the tree algorithm and is used together with the payload to compute the leaf hash. A use case for this field is to implement blinding.

TODO: maybe rename `extra_data`

### Signed Merkle Tree Multiproof

TODO: define a multi-leaf variant of a signed Merkle tree proof like in:

- https://github.com/transmute-industries/merkle-proof
- https://transmute-industries.github.io/merkle-disclosure-proof-2021/

TODO: consider using sparse multiproofs, see https://medium.com/@jgm.orinoco/understanding-sparse-merkle-multiproofs-9b9f049e8f08 and https://arxiv.org/pdf/2002.07648.pdf

## Merkle Tree Algorithms

This document establishes a registry of Merkle tree algorithms with the following initial contents:

 Name           | Label | Description
----------------|-------|------------
Reserved        | 0     |
CCF_SHA256      | 1     | CCF with SHA-256
RFC6962_SHA256  | 2     | RFC6962 with SHA-256
RFC6962_BL_SHA256  | 3     | RFC6962 with blinding and SHA-256
QLDB_SHA256     | 4     | QLDB with SHA-256

Each tree algorithm defines how to compute the root node from a sequence of leaves each represented by payload and extra data. Extra data is algorithm-specific and should be considered opaque.

### CCF_SHA256

For n > 1 inputs, let k be the largest power of two smaller than n.

```c
MTH({d(0)}) = SHA-256(d(0))
MTH(D[n]) = SHA-256(MTH(D[0:k]) || MTH(D[k:n]))
```

where `d(0)` is computed as:

```c
d(0) = writeset_digest || SHA-256(commit_evidence) || SHA-256(payload)
```

with extra data defined as:

```c
ExtraData = bstr .cbor [
    writeset_digest: bstr .size 32
    commit_evidence: bstr
]
```

### RFC6962_SHA256

For n > 1 inputs, let k be the largest power of two smaller than n.

```c
MTH({d(0)}) = SHA-256(0x00 || d(0))
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

where `d(0)` is the payload. This algorithm takes no extra data.

### RFC6962_BL_SHA256

For n > 1 inputs, let k be the largest power of two smaller than n.

```c
MTH({d(0)}) = SHA-256(0x00 || d(0))
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

where `d(0)` is computed as:

```c
d(0) = nonce || payload
```

with extra data defined as:

```c
ExtraData = bstr .size 32  ; nonce
```

### QLDB_SHA256

For n > 1 inputs, let k be the largest power of two smaller than n.

```c
MTH({d(0)}) = SHA-256(d(0))
MTH(D[n]) = SHA-256(DOT(MTH(D[0:k]), MTH(D[k:n])))
DOT(H1, H2) = if H1 < H2 then H1 || H2 else H2 || H1
```

where `d(0)` is the payload. This algorithm takes no extra data.
