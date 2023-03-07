from typing import Optional, List, Callable, Union, Type
from dataclasses import dataclass
from abc import ABC, abstractmethod
import hashlib
import cbor2

SHA256 = lambda data: hashlib.sha256(data).digest()
SHA3_256 = lambda data: hashlib.sha3_256(data).digest()


# TODO Is Entry the right name for this?
@dataclass
class Entry:
    payload: bytes
    extra_data: Optional[bytes]


class InclusionPath(ABC):
    @abstractmethod
    def encode(self) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def decode(cls, data: bytes) -> 'InclusionPath':
        pass


@dataclass
class IndexAwareInclusionPath(InclusionPath):
    TAG = 1234

    index: int
    hashes: List[bytes]

    def verify(self, tree_algorithm: 'TreeAlgorithm', root: bytes, entry_hash: bytes, tree_size: int) -> bool:
        return tree_algorithm.compute_root_from_index_aware_inclusion_path(
            entry_hash, tree_size, self) == root

    def encode(self):
        return cbor2.dumps(cbor2.CBORTag(self.TAG,
            [self.index, self.hashes]))
    
    @classmethod
    def decode(cls, data):
        decoded = cbor2.loads(data)
        assert isinstance(decoded, cbor2.CBORTag)
        assert decoded.tag == cls.TAG
        index, hashes = decoded.value
        return cls(index=index, hashes=hashes)

    def __str__(self):
        short_hashes = ' '.join(h.hex()[:8] for h in self.hashes)
        return f'Hashes: {short_hashes}, Index: {self.index}'


@dataclass
class IndexUnawareInclusionPath(InclusionPath):
    TAG = 1235

    hashes: List[bytes]
    is_left: List[bool]

    def verify(self, tree_algorithm: 'TreeAlgorithm', root: bytes, entry_hash: bytes) -> bool:
        return tree_algorithm.compute_root_from_index_unaware_inclusion_path(
            entry_hash, self) == root

    def encode(self):
        assert len(self.hashes) == len(self.is_left)
        assert len(self.is_left) <= 64
        flags = 0
        for i, is_left in enumerate(self.is_left):
            if is_left:
                flags |= 1 << i

        return cbor2.dumps(cbor2.CBORTag(self.TAG,
            [self.hashes, flags]))
    
    @classmethod
    def decode(cls, data):
        decoded = cbor2.loads(data)
        assert isinstance(decoded, cbor2.CBORTag)
        assert decoded.tag == cls.TAG
        hashes, flags = decoded.value
        is_left = []
        for i in range(len(hashes)):
            is_left.append(flags & (1 << i) != 0)
        return cls(hashes=hashes, is_left=is_left)

    def __str__(self):
        short_hashes = ' '.join(h.hex()[:8] for h in self.hashes)
        return f'Hashes: {short_hashes}, Left: {self.is_left}'


@dataclass
class UndirectionalInclusionPath(InclusionPath):
    TAG = 1236

    hashes: List[bytes]

    def verify(self, tree_algorithm: 'TreeAlgorithm', root: bytes, entry_hash: bytes) -> bool:
        return tree_algorithm.compute_root_from_undirectional_inclusion_path(
            entry_hash, self) == root
    
    def encode(self):
        return cbor2.dumps(cbor2.CBORTag(self.TAG, self.hashes))
    
    @classmethod
    def decode(cls, data):
        decoded = cbor2.loads(data)
        assert isinstance(decoded, cbor2.CBORTag)
        assert decoded.tag == cls.TAG
        hashes = decoded.value
        return cls(hashes=hashes)

    def __str__(self):
        short_hashes = ' '.join(h.hex()[:8] for h in self.hashes)
        return f'Hashes: {short_hashes}'


class TreeAlgorithm(ABC):
    IDENTIFIER: Union[int, str]
    SUPPORTED_INCLUSION_PATH_TYPES: List[Type]

    @abstractmethod
    def hash_entry(self, entry: Entry) -> bytes:
        pass

    @abstractmethod
    def generate_index_aware_inclusion_path(self, hashes: List[bytes], index: int) -> IndexAwareInclusionPath:
        pass

    @abstractmethod
    def generate_index_unaware_inclusion_path(self, hashes: List[bytes], index: int) -> IndexUnawareInclusionPath:
        pass

    @abstractmethod
    def generate_undirectional_inclusion_path(self, hashes: List[bytes], index: int) -> UndirectionalInclusionPath:
        pass

    @abstractmethod
    def compute_root_from_hashed_entries(hashes: List[bytes]) -> bytes:
        pass

    @abstractmethod
    def compute_root_from_index_aware_inclusion_path(self, entry_hash: bytes, tree_size: int, path: IndexAwareInclusionPath) -> bytes:
        pass

    @abstractmethod
    def compute_root_from_index_unaware_inclusion_path(self, entry_hash: bytes, path: IndexUnawareInclusionPath) -> bytes:
        pass

    @abstractmethod
    def compute_root_from_undirectional_inclusion_path(self, entry_hash: bytes, path: UndirectionalInclusionPath) -> bytes:
        pass


class CommonTreeAlgorithm(TreeAlgorithm):
    """Common implementations used by most tree algorithms."""

    @abstractmethod
    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        pass

    def generate_tree(self, entry_hashes: List[bytes]) -> List[List[bytes]]:
        hashes = entry_hashes
        tree = [hashes]
        while len(hashes) > 1:
            level_size = len(hashes)
            solo_leaf = None
            if level_size % 2 == 1:
                level_size -= 1
                solo_leaf = hashes[-1]
            hashes = [self.hash_intermediate(hashes[i], hashes[i+1])
                      for i in range(0, level_size, 2)
                     ] + ([solo_leaf] if solo_leaf is not None else [])
            tree.append(hashes)
        return tree

    def compute_root_from_hashed_entries(self, entry_hashes: List[bytes]) -> bytes:
        tree = self.generate_tree(entry_hashes)
        return tree[-1][0]

    def compute_root_from_index_unaware_inclusion_path(self, entry_hash: bytes, path: IndexUnawareInclusionPath) -> bytes:
        self.check_supports_inclusion_path_type(IndexUnawareInclusionPath)
        
        h = entry_hash
        for (is_left, sibling) in zip(path.is_left, path.hashes):
            if is_left:
                h = self.hash_intermediate(sibling, h)
            else:
                h = self.hash_intermediate(h, sibling)
        return h

    def compute_root_from_index_aware_inclusion_path(self, entry_hash: bytes, tree_size: int, path: IndexAwareInclusionPath) -> bytes:
        self.check_supports_inclusion_path_type(IndexAwareInclusionPath)

        # Adapted from https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1.3.2.

        LSB = lambda x: x & 1

        (entry_index, hashes) = path.index, path.hashes
        
        if entry_index >= tree_size:
            raise ValueError("Entry index is out of range")
        fn = entry_index
        sn = tree_size - 1
        r = entry_hash
        for p in hashes:
            if sn == 0:
                raise ValueError("Inclusion path is too long")
            if LSB(fn) == 1 or fn == sn:
                r = self.hash_intermediate(p, r)
                if LSB(fn) == 0:
                    while LSB(fn) == 0 and fn != 0:
                        fn = fn >> 1
                        sn = sn >> 1
            else:
                r = self.hash_intermediate(r, p)
            fn = fn >> 1
            sn = sn >> 1
        if sn != 0:
            raise ValueError("Inclusion path is too short")
        return r

    def compute_root_from_undirectional_inclusion_path(self, entry_hash: bytes, path: UndirectionalInclusionPath) -> bytes:
        self.check_supports_inclusion_path_type(UndirectionalInclusionPath)
        
        h = entry_hash
        for sibling in path.hashes:
            h = self.hash_intermediate(h, sibling)
        return h
   
    def generate_index_unaware_inclusion_path(self, entry_hashes: List[bytes], index: int) -> IndexUnawareInclusionPath:
        self.check_supports_inclusion_path_type(IndexUnawareInclusionPath)
        
        assert 0 <= index and index < len(entry_hashes)
        path = []
        is_left = []
        tree = self.generate_tree(entry_hashes)
        for level in tree:
            if index % 2 == 1:
                path.append(level[index - 1])
                is_left.append(True)
            elif index < len(level) - 1:
                path.append(level[index + 1])
                is_left.append(False)
            index //= 2
        return IndexUnawareInclusionPath(path, is_left)

    def generate_index_aware_inclusion_path(self, entry_hashes: List[bytes], index: int) -> IndexAwareInclusionPath:
        self.check_supports_inclusion_path_type(IndexAwareInclusionPath)
        
        path = self.generate_index_unaware_inclusion_path(entry_hashes, index)
        return IndexAwareInclusionPath(index, path.hashes)

    def generate_undirectional_inclusion_path(self, entry_hashes: List[bytes], index: int) -> UndirectionalInclusionPath:
        self.check_supports_inclusion_path_type(UndirectionalInclusionPath)
        
        path = self.generate_index_unaware_inclusion_path(entry_hashes, index)
        return UndirectionalInclusionPath(path.hashes)
    
    def check_supports_inclusion_path_type(self, typ: Type):
        if typ not in self.SUPPORTED_INCLUSION_PATH_TYPES:
            raise RuntimeError(f"This tree algorithm does not support inclusion paths of type {typ}")


class BaseCCFTreeAlgorithm(CommonTreeAlgorithm):
    SUPPORTED_INCLUSION_PATH_TYPES = [
        IndexAwareInclusionPath,
        IndexUnawareInclusionPath,
    ]

    def __init__(self, hash_fn: Callable):
        self.hash_fn = hash_fn

    def hash_entry(self, entry: Entry) -> bytes:
        (writeset_digest, commit_evidence) = cbor2.loads(entry.extra_data)
        commit_evidence_hash = self.hash_fn(commit_evidence)
        payload_hash = self.hash_fn(entry.payload)
        return self.hash_fn(writeset_digest + commit_evidence_hash + payload_hash)

    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        return self.hash_fn(left + right)


class CCFSha256TreeAlgorithm(BaseCCFTreeAlgorithm):
    IDENTIFIER = 1

    def __init__(self):
        super().__init__(SHA256)


class BaseRFC6962TreeAlgorithm(CommonTreeAlgorithm):
    SUPPORTED_INCLUSION_PATH_TYPES = [
        IndexAwareInclusionPath,
        IndexUnawareInclusionPath,
    ]

    def __init__(self, hash_fn: Callable):
        self.hash_fn = hash_fn
              
    def hash_entry(self, entry: Entry) -> bytes:
        assert entry.extra_data is None
        return self.hash_fn(b'\x00' + entry.payload)
    
    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        return self.hash_fn(b'\x01' + left + right)
    

class RFC6962Sha256TreeAlgorithm(BaseRFC6962TreeAlgorithm):
    IDENTIFIER = 2

    def __init__(self):
        super().__init__(SHA256)


class BaseQldbTreeAlgorithm(CommonTreeAlgorithm):
    SUPPORTED_INCLUSION_PATH_TYPES = [
        IndexUnawareInclusionPath,
        UndirectionalInclusionPath,
    ]

    def __init__(self, hash_fn: Callable):
        self.hash_fn = hash_fn
       
    def hash_entry(self, entry: Entry) -> bytes:
        assert entry.extra_data is None
        return self.hash_fn(entry.payload)
    
    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        if left < right:
            return self.hash_fn(left + right)
        else:
            return self.hash_fn(right + left)


class QldbSha256TreeAlgorithm(BaseQldbTreeAlgorithm):
    IDENTIFIER = 4

    def __init__(self):
        super().__init__(SHA256)


class BaseOpenZeppelinTreeAlgorithm(CommonTreeAlgorithm):
    SUPPORTED_INCLUSION_PATH_TYPES = [
        IndexUnawareInclusionPath,
        UndirectionalInclusionPath,
    ]

    def __init__(self, hash_fn: Callable):
        self.hash_fn = hash_fn
    
    def hash_entry(self, entry: Entry) -> bytes:
        assert entry.extra_data is None
        return self.hash_fn(self.hash_fn(entry.payload))
    
    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        if left < right:
            return self.hash_fn(left + right)
        else:
            return self.hash_fn(right + left)

    def generate_tree(self, entry_hashes: List[bytes]) -> List[List[bytes]]:
        entry_hashes = sorted(entry_hashes)
        return super().generate_tree(entry_hashes)
    
    def generate_index_unaware_inclusion_path(self, hashes: List[bytes], index: int) -> IndexUnawareInclusionPath:
        entry_hashes = sorted(hashes)
        idx = entry_hashes.index(hashes[index])
        return super().generate_index_unaware_inclusion_path(entry_hashes, idx)

    def generate_undirectional_inclusion_path(self, hashes: List[bytes], index: int) -> UndirectionalInclusionPath:
        entry_hashes = sorted(hashes)
        idx = entry_hashes.index(hashes[index])
        return super().generate_undirectional_inclusion_path(entry_hashes, idx)


class OpenZeppelinKeccak256TreeAlgorithm(BaseOpenZeppelinTreeAlgorithm):
    IDENTIFIER = 5

    def __init__(self):
        # TODO is keccak256 the same as sha3_256?
        super().__init__(SHA3_256)


# Note that for new systems, Bitcoin's Merkle tree algorithm
# should not be used due to CVE-2012-2459. It is included here to explore
# the design space and make sure that the API is flexible enough.
class BaseBitcoinTreeAlgorithm(CommonTreeAlgorithm):
    SUPPORTED_INCLUSION_PATH_TYPES = [
        IndexAwareInclusionPath,
        IndexUnawareInclusionPath,
    ]

    def __init__(self, hash_fn: Callable):
        self.hash_fn = hash_fn
    
    def hash_entry(self, entry: Entry) -> bytes:
        assert entry.extra_data is None
        return self.hash_fn(self.hash_fn(entry.payload))
    
    def hash_intermediate(self, left: bytes, right: bytes) -> bytes:
        return self.hash_fn(self.hash_fn(left + right))
    
    def generate_tree(self, entry_hashes: List[bytes]) -> List[List[bytes]]:
        hashes = list(entry_hashes)
        tree = [hashes]
        while len(hashes) > 1:
            if len(hashes) % 2 == 1:
                hashes.append(hashes[-1])
            hashes = [self.hash_intermediate(hashes[i], hashes[i+1])
                      for i in range(0, len(hashes), 2)]
            tree.append(hashes)
        return tree
    
    def compute_root_from_index_aware_inclusion_path(self, entry_hash: bytes, tree_size: int, path: IndexAwareInclusionPath) -> bytes:
        index = path.index
        hashes = path.hashes
        h = entry_hash
        for i in range(len(hashes)):
            if index % 2 == 0:
                h = self.hash_intermediate(h, hashes[i])
            else:
                h = self.hash_intermediate(hashes[i], h)
            index = index // 2
        return h
    

class BitcoinSha256TreeAlgorithm(BaseBitcoinTreeAlgorithm):
    IDENTIFIER = 6

    def __init__(self):
        super().__init__(SHA256)
