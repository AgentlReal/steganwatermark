"""
GhostShare Plausible Deniability Module.

Provides collision-free coordinate partitioning and deterministic PRNG index generation
so that Real and Decoy payloads reside in strictly disjoint pixel spaces (I_real ∩ I_decoy = ∅).
"""

import hashlib
from typing import Dict, List, Tuple
import numpy as np


PARTITION_FULL = "full"
PARTITION_EVEN = "even"
PARTITION_ODD = "odd"

CANDIDATE_PARTITIONS = [PARTITION_FULL, PARTITION_EVEN, PARTITION_ODD]


def get_partition_indices(total_elements: int, partition_name: str) -> np.ndarray:
    """
    Returns base coordinate array for the specified partition.
    
    Partitions:
      - 'full': All elements [0, 1, 2, ..., N-1]
      - 'even': Even elements [0, 2, 4, ..., N-2]
      - 'odd':  Odd elements  [1, 3, 5, ..., N-1]
    """
    if partition_name == PARTITION_FULL:
        return np.arange(total_elements, dtype=np.int64)
    elif partition_name == PARTITION_EVEN:
        return np.arange(0, total_elements, 2, dtype=np.int64)
    elif partition_name == PARTITION_ODD:
        return np.arange(1, total_elements, 2, dtype=np.int64)
    else:
        raise ValueError(f"Unknown partition name: '{partition_name}'.")


def generate_shuffled_partition_indices(
    total_elements: int,
    passphrase: str,
    partition_name: str = PARTITION_FULL,
) -> np.ndarray:
    """
    Generates a deterministic pseudo-random permutation of indices within the specified partition
    using a 64-bit integer seed derived from SHA-256(passphrase).
    """
    base_indices = get_partition_indices(total_elements, partition_name)
    if len(base_indices) == 0:
        return base_indices

    # Derive seed from passphrase
    seed_hash = hashlib.sha256(passphrase.encode("utf-8")).digest()
    seed_int = int.from_bytes(seed_hash[:8], byteorder="big")

    rng = np.random.default_rng(seed_int)
    shuffled = base_indices.copy()
    rng.shuffle(shuffled)
    return shuffled
