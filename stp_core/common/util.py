# TODO: move it to plenum-util repo


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


def lxor(a, b):
    # Logical xor of 2 items, return true when one of them is truthy and
    # one of them falsy
    return bool(a) != bool(b)