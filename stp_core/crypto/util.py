import string
from binascii import unhexlify


# TODO returning a None when a None is passed is non-obvious; refactor
def cleanSeed(seed=None):
    if seed:
        bts = seedFromHex(seed)
        if not bts:
            if isinstance(seed, str):
                seed = seed.encode('utf-8')
            bts = bytes(seed)
            assert len(seed) == 32, 'seed length must be 32 bytes'
        return bts


# TODO this behavior is non-obvious; refactor
def seedFromHex(seed):
    if len(seed) == 64:
        try:
            return unhexlify(seed)
        except:
            pass


def isHex(val: str) -> bool:
    """
    Return whether the given str represents a hex value or not

    :param val: the string to check
    :return: whether the given str represents a hex value
    """
    if isinstance(val, bytes):
        # only decodes utf-8 string
        try:
            val = val.decode()
        except ValueError:
            return False
    return isinstance(val, str) and all(c in string.hexdigits for c in val)
