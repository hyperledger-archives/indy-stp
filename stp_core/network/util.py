import logging
import socket
from collections import OrderedDict
from typing import List

import itertools

import math
from libnacl import crypto_hash_sha256


def checkPortAvailable(ha):
    """Checks whether the given port is available"""
    # Not sure why OS would allow binding to one type and not other.
    # Checking for port available for TCP and UDP, this is done since
    # either RAET (UDP) or CurveZMQ(TCP) could have been used
    sockTypes = (socket.SOCK_DGRAM, socket.SOCK_STREAM)
    for typ in sockTypes:
        sock = socket.socket(socket.AF_INET, typ)
        try:
            sock.bind(ha)
        except BaseException as ex:
            logging.warning("Checked port availability for opening "
                            "as {} but address was already in use: {}".
                            format(typ, ha))
            raise ex
        finally:
            sock.close()


def evenCompare(a: str, b: str) -> bool:
    """
    A deterministic but more evenly distributed comparator than simple alphabetical.
    Useful when comparing consecutive strings and an even distribution is needed.
    Provides an even chance of returning true as often as false
    """
    ab = a.encode('utf-8')
    bb = b.encode('utf-8')
    ac = crypto_hash_sha256(ab)
    bc = crypto_hash_sha256(bb)
    return ac < bc


def distributedConnectionMap(names: List[str]) -> OrderedDict:
    """
    Create a map where every node is connected every other node.
    Assume each key in the returned dictionary to be connected to each item in
    its value(list).

    :param names: a list of node names
    :return: a dictionary of name -> list(name).
    """
    names.sort()
    combos = list(itertools.combinations(names, 2))
    maxPer = math.ceil(len(list(combos)) / len(names))
    # maxconns = math.ceil(len(names) / 2)
    connmap = OrderedDict((n, []) for n in names)
    for a, b in combos:
        if len(connmap[a]) < maxPer:
            connmap[a].append(b)
        else:
            connmap[b].append(a)
    return connmap