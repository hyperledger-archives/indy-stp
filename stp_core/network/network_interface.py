import time
from abc import abstractmethod
from typing import Set

from stp_core.common.log import getlogger
from stp_core.network.exceptions import RemoteNotFound, DuplicateRemotes
from stp_core.types import HA

logger = getlogger()


class NetworkInterface:
    localips = ['127.0.0.1', '0.0.0.0']

    @property
    @abstractmethod
    def remotes(self):
        """
        Return all remote nodes (both connected and not)
        """
        pass

    @property
    @abstractmethod
    def created(self):
        pass

    @staticmethod
    @abstractmethod
    def isRemoteConnected(r) -> bool:
        """
        A node is considered to be connected if it is joined, allowed and alived.

        :param r: the remote to check
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def initLocalKeys(name, baseDir, sigseed, override=False):
        raise NotImplementedError

    @staticmethod
    def initRemoteKeys(name, remoteName, baseDir, verkey, override=False):
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def areKeysSetup(name, baseDir):
        raise NotImplementedError

    @abstractmethod
    def removeRemote(self, r):
        raise NotImplementedError

    @abstractmethod
    def transmit(self, msg, uid, timeout=None):
        raise NotImplementedError

    @abstractmethod
    def start(self):
        raise NotImplementedError

    @abstractmethod
    def stop(self):
        raise NotImplementedError

    @abstractmethod
    def connect(self, name=None, remoteId=None, ha=None, verKey=None, publicKey=None):
        raise NotImplementedError

    @property
    def age(self):
        """
        Returns the time elapsed since this stack was created
        """
        return time.perf_counter() - self.created

    # TODO: Does this serve the same purpose as `conns`, if yes then remove
    @property
    def connecteds(self) -> Set[str]:
        """
        Return the names of the remote nodes this node is connected to. Not all of these nodes may be used for communication (as opposed to conns property)
        """
        return {r.name for r in self.remotes.values()
                if self.isRemoteConnected(r)}

    @property
    def conns(self) -> Set[str]:
        """
        Get connections of this node which participate in the communication

        :return: set of names of the connected nodes
        """
        return self._conns

    @conns.setter
    def conns(self, value: Set[str]) -> None:
        """
        Updates the connection count of this node if not already done.
        """
        if not self._conns == value:
            old = self._conns
            self._conns = value
            ins = value - old
            outs = old - value
            logger.debug("{}'s connections changed from {} to {}".format(self,
                                                                         old,
                                                                         value))
            self._connsChanged(ins, outs)

    def checkConns(self):
        """
        Evaluate the connected nodes
        """
        self.conns = self.connecteds

    def _connsChanged(self, ins: Set[str], outs: Set[str]) -> None:
        """
        A series of operations to perform once a connection count has changed.

        - Set f to max number of failures this system can handle.
        - Set status to one of started, started_hungry or starting depending on
            the number of protocol instances.
        - Check protocol instances. See `checkProtocolInstaces()`

        :param ins: new nodes connected
        :param outs: nodes no longer connected
        """
        for o in outs:
            logger.info("{} disconnected from {}".format(self, o),
                        extra={"cli": "IMPORTANT",
                               "tags": ["connected"]})
        for i in ins:
            logger.info("{} now connected to {}".format(self, i),
                        extra={"cli": "IMPORTANT",
                               "tags": ["connected"]})

            # remove remotes for same ha when a connection is made
            remote = self.getRemote(i)
            others = [r for r in self.remotes.values()
                      if r.ha == remote.ha and r.name != i]
            for o in others:
                logger.debug("{} removing other remote".format(self))
                self.removeRemote(o)

        self.onConnsChanged(ins, outs)

    def onConnsChanged(self, ins: Set[str], outs: Set[str]):
        """
        Subclasses can override
        """
        pass


    def isConnectedTo(self, name: str = None, ha: HA = None):
        try:
            remote = self.getRemote(name, ha)
        except RemoteNotFound:
            return False
        return self.isRemoteConnected(remote)

    def getRemote(self, name: str = None, ha: HA = None):
        """
        Find the remote by name or ha.

        :param name: the name of the remote to find
        :param ha: host address pair the remote to find
        :raises: RemoteNotFound
        """
        return self.findInRemotesByName(name) if name else \
            self.findInRemotesByHA(ha)

    def findInRemotesByHA(self, remoteHa: HA):
        remotes = [r for r in self.remotes.values()
                   if r.ha == remoteHa]
        if len(remotes) > 1:
            raise DuplicateRemotes(remotes)
        if not remotes:
            raise RemoteNotFound(remoteHa)
        return remotes[0]

    def findInRemotesByName(self, name: str):
        """
        Find the remote by name.

        :param name: the name of the remote to find
        :raises: RemoteNotFound
        """
        remotes = [r for r in self.remotes.values()
                   if r.name == name]
        if len(remotes) > 1:
            raise DuplicateRemotes(remotes)
        if not remotes:
            raise RemoteNotFound(name)
        return remotes[0]

    def hasRemote(self, name):
        try:
            self.getRemote(name=name)
            return True
        except RemoteNotFound:
            return False

    def removeRemoteByName(self, name: str) -> int:
        """
        Remove the remote by name.

        :param name: the name of the remote to remove
        :raises: RemoteNotFound
        """
        remote = self.getRemote(name)
        rid = remote.uid
        self.removeRemote(remote)
        return rid

    def getHa(self, name):
        try:
            remote = self.getRemote(name)
        except RemoteNotFound:
            return None
        return remote.ha

    def sameAddr(self, ha, ha2) -> bool:
        """
        Check whether the two arguments correspond to the same address
        """
        if ha == ha2:
            return True
        elif ha[1] != ha2[1]:
            return False
        else:
            return ha[0] in self.localips and ha2[0] in self.localips

    def remotesByConnected(self):
        """
        Partitions the remotes into connected and disconnected

        :return: tuple(connected remotes, disconnected remotes)
        """
        conns, disconns = [], []
        for r in self.remotes.values():
            array = conns if self.isRemoteConnected(r) else disconns
            array.append(r)
        return conns, disconns
