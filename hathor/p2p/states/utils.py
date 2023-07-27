import re
from hathor.indexes.height_index import HeightInfo


def to_height_info(raw: tuple[int, str]) -> HeightInfo:
    """ Instantiate HeightInfo from a literal tuple.
    """
    if not (isinstance(raw, list) and len(raw) == 2):
        raise ValueError(f"block_info_raw must be a tuple with length 3. We got {raw}.")

    height, id = raw

    if not isinstance(id, str):
        raise ValueError(f"hash_hex must be a string. We got {id}.")
    hash_pattern = r'[a-fA-F\d]{64}'
    if not re.match(hash_pattern, id):
        raise ValueError(f"hash_hex must be valid. We got {id}.")
    if not isinstance(height, int):
        raise ValueError(f"height must be an integer. We got {height}.")
    if height < 0:
        raise ValueError(f"height must greater than or equal to 0. We got {height}.")

    return HeightInfo(height, bytes.fromhex(id))
