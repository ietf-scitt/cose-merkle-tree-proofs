from hashlib import sha256
import pytest
import cbor2

import merkle_proofs.tree_algorithms as ta


@pytest.mark.parametrize('tree_alg_class', [
    'CCFSha256TreeAlgorithm',
    'RFC6962Sha256TreeAlgorithm',
    'QldbSha256TreeAlgorithm',
    'OpenZeppelinKeccak256TreeAlgorithm',
    'BitcoinSha256TreeAlgorithm',
])
@pytest.mark.parametrize('entry_count,path_index', [
    (1, 0), (2, 0), (2, 1), (6, 4)
])
def test_inclusion_path(tree_alg_class, entry_count: int, path_index: int):
    tree_alg = getattr(ta, tree_alg_class)()
    
    # For the sake of this test, extra_data is constant for all entries.
    if isinstance(tree_alg, ta.CCFSha256TreeAlgorithm):
        extra_data = cbor2.dumps([sha256(b'writeset').digest(), b'commit evidence'])
    else:
        extra_data = None
    
    entries = [ta.Entry(f'entry_{i}'.encode(), extra_data)
               for i in range(entry_count)]

    entry_hashes = [tree_alg.hash_entry(e) for e in entries]
    root = tree_alg.compute_root_from_hashed_entries(entry_hashes)

    if ta.IndexUnawareInclusionPath in tree_alg.SUPPORTED_INCLUSION_PATH_TYPES:
        path = tree_alg.generate_index_unaware_inclusion_path(entry_hashes, path_index)
        assert path.verify(tree_alg, root, entry_hashes[path_index])

    if ta.IndexAwareInclusionPath in tree_alg.SUPPORTED_INCLUSION_PATH_TYPES:
        path = tree_alg.generate_index_aware_inclusion_path(entry_hashes, path_index)
        assert path.verify(tree_alg, root, entry_hashes[path_index], len(entries))

    if ta.UndirectionalInclusionPath in tree_alg.SUPPORTED_INCLUSION_PATH_TYPES:
        path = tree_alg.generate_undirectional_inclusion_path(entry_hashes, path_index)
        assert path.verify(tree_alg, root, entry_hashes[path_index])
