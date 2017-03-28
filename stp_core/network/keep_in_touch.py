from abc import abstractmethod
from typing import Dict, Set

import time
from stp_core.network.network_interface import NetworkInterface
from stp_core.ratchet import Ratchet
from stp_core.types import HA


class KITNetworkInterface:
    # Keep In Touch Stack which maintains connections mentioned in
    # its registry
    def __init__(self, registry: Dict[str, HA]):
        self.registry = registry

        self.lastcheck = {}  # type: Dict[int, Tuple[int, float]]
        self.ratchet = Ratchet(a=8, b=0.198, c=-4, base=8, peak=3600)

        # holds the last time we checked remotes
        self.nextCheck = 0

    @abstractmethod
    def maintainConnections(self, force=False):
        """
        Ensure appropriate connections.

        """
        raise NotImplementedError

    @abstractmethod
    def reconcileNodeReg(self):
        raise NotImplementedError

    def serviceLifecycle(self) -> None:
        """
        Function that does the following activities if the node is going:
        (See `Status.going`)

        - check connections (See `checkConns`)
        - maintain connections (See `maintainConnections`)
        """
        self.checkConns()
        self.maintainConnections()

    def findInNodeRegByHA(self, remoteHa):
        """
        Returns the name of the remote by HA if found in the node registry, else
        returns None
        """
        regName = [nm for nm, ha in self.registry.items()
                   if self.sameAddr(ha, remoteHa)]
        if len(regName) > 1:
            raise RuntimeError("more than one node registry entry with the "
                               "same ha {}: {}".format(remoteHa, regName))
        if regName:
            return regName[0]
        return None


    def getRemoteName(self, remote):
        """
        Returns the name of the remote object if found in node registry.

        :param remote: the remote object
        """
        if remote.name not in self.registry:
            find = [name for name, ha in self.registry.items()
                    if ha == remote.ha]
            assert len(find) == 1
            return find[0]
        return remote.name

    @property
    def notConnectedNodes(self) -> Set[str]:
        """
        Returns the names of nodes in the registry this node is NOT connected
        to.
        """
        return set(self.registry.keys()) - self.conns
