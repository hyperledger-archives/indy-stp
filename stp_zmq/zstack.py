import inspect

try:
    import ujson as json
except ImportError:
    import json

import os
import shutil
import sys
import time
from abc import abstractmethod
from binascii import hexlify, unhexlify
from collections import deque
from typing import Dict, Mapping, Callable, Tuple, Any, Union
from typing import Set

# import stp_zmq.asyncio
import zmq.auth
from stp_core.crypto.nacl_wrappers import Signer, Verifier
from stp_core.crypto.util import isHex, ed25519PkToCurve25519
from stp_core.network.auth_mode import AuthMode
from stp_core.network.exceptions import PublicKeyNotFoundOnDisk, VerKeyNotFoundOnDisk
from stp_core.network.keep_in_touch import KITNetworkInterface
from stp_zmq.authenticator import MultiZapAuthenticator
from zmq.utils import z85
from zmq.utils.monitor import recv_monitor_message

import zmq
from stp_core.common.log import getlogger
from stp_core.network.network_interface import NetworkInterface
from stp_core.ratchet import Ratchet
from stp_core.types import HA
from stp_zmq.util import createEncAndSigKeys, \
    moveKeyFilesToCorrectLocations, createCertsFromKeys

logger = getlogger()

DEFAULT_LISTENER_QUOTA = 100
DEFAULT_REMOTE_QUOTA = 100

# TODO: Separate directories are maintainer for public keys and verification
# keys of remote, same direcotry can be used, infact preserve only
# verification key and generate public key from that. Same concern regarding
# signing and private keys


class Remote:
    def __init__(self, name, ha, verKey, publicKey):
        # TODO, remove *args, **kwargs after removing test

        # Every remote has a unique name per stack, the name can be the
        # public key of the other end
        self.name = name
        self.ha = ha
        # self.publicKey is the public key of the other end of the remote
        self.publicKey = publicKey
        # self.verKey is the verification key of the other end of the remote
        self.verKey = verKey
        self.socket = None
        # TODO: A stack should have a monitor and it should identify remote
        # by endpoint

        self._numOfReconnects = 0
        self._isConnected = False
        self._lastConnectedAt = None

        # Currently keeping uid field to resemble RAET RemoteEstate
        self.uid = name

    def __repr__(self):
        return '{}:{}'.format(self.name, self.ha)

    @property
    def isConnected(self):
        if not self._isConnected:
            return False
        lost = self.hasLostConnection
        if lost:
            self._isConnected = False
            return False
        return True

    def setConnected(self):
        self._numOfReconnects += 1
        self._isConnected = True
        self._lastConnectedAt = time.perf_counter()

    def firstConnect(self):
        return self._numOfReconnects == 0

    def connect(self, context, localPubKey, localSecKey, typ=None):
        typ = typ or zmq.DEALER
        sock = context.socket(typ)
        sock.curve_publickey = localPubKey
        sock.curve_secretkey = localSecKey
        sock.curve_serverkey = self.publicKey
        sock.identity = localPubKey
        # sock.setsockopt(test.PROBE_ROUTER, 1)
        sock.setsockopt(zmq.TCP_KEEPALIVE, 1)
        sock.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 1000)
        addr = 'tcp://{}:{}'.format(*self.ha)
        sock.connect(addr)
        self.socket = sock
        logger.trace('connecting socket {} {} to remote {}'.
                     format(self.socket.FD, self.socket.underlying, self))

    def disconnect(self):
        logger.debug('disconnecting remote {}'.format(self))
        if self.socket:
            logger.trace('disconnecting socket {} {}'.
                         format(self.socket.FD, self.socket.underlying))

            if self.socket._monitor_socket:
                logger.trace('{} closing monitor socket'.format(self))
                self.socket._monitor_socket.linger = 0
                self.socket.monitor(None, 0)
                self.socket._monitor_socket = None
                # self.socket.disable_monitor()
            self.socket.close(linger=0)
            self.socket = None
        else:
            logger.debug('{} close was called on a null socket, maybe close is '
                         'being called twice.'.format(self))

        self._isConnected = False

    @property
    def hasLostConnection(self):

        if self.socket is None:
            logger.warning('Remote {} already disconnected'.format(self))
            return False

        events = self._lastSocketEvents()

        if events:
            logger.trace('Remote {} has monitor events: {}'.
                         format(self, events))

        # noinspection PyUnresolvedReferences
        if zmq.EVENT_DISCONNECTED in events or zmq.EVENT_CLOSED in events:
            logger.debug('{} found disconnected event on monitor'.format(self))

            # Reverse events list since list has no builtin to get last index
            events.reverse()

            def eventIndex(eventName):
                try:
                    return events.index(eventName)
                except ValueError:
                    return sys.maxsize

            connected = eventIndex(zmq.EVENT_CONNECTED)
            delayed = eventIndex(zmq.EVENT_CONNECT_DELAYED)
            disconnected = min(eventIndex(zmq.EVENT_DISCONNECTED),
                               eventIndex(zmq.EVENT_CLOSED))
            if disconnected < connected and disconnected < delayed:
                return True

        return False

    def _lastSocketEvents(self, nonBlock=True):
        monitor = self.socket.get_monitor_socket()
        events = []
        # noinspection PyUnresolvedReferences
        flags = zmq.NOBLOCK if nonBlock else 0
        while True:
            try:
                # noinspection PyUnresolvedReferences
                message = recv_monitor_message(monitor, flags)
                events.append(message['event'])
            except zmq.Again:
                break
        return events


# TODO: Use Async io
class ZStack(NetworkInterface):
    # Assuming only one listener per stack for now.

    MAX_SOCKETS = 16384 if sys.platform != 'win32' else None

    PublicKeyDirName = 'public_keys'
    PrivateKeyDirName = 'private_keys'
    VerifKeyDirName = 'verif_keys'
    SigKeyDirName = 'sig_keys'

    sigLen = 64
    pingMessage = 'pi'
    pongMessage = 'po'
    healthMessages = {pingMessage.encode(), pongMessage.encode()}

    # TODO: This is not implemented, implement this
    messageTimeout = 3

    def __init__(self, name, ha, basedirpath, msgHandler, restricted=True,
                 seed=None, onlyListener=False,
                 listenerQuota=DEFAULT_LISTENER_QUOTA, remoteQuota=DEFAULT_REMOTE_QUOTA):
        self._name = name
        self.ha = ha
        self.basedirpath = basedirpath
        self.msgHandler = msgHandler
        self.seed = seed
        self.listenerQuota = listenerQuota
        self.remoteQuota = remoteQuota

        self.homeDir = None
        # As of now there would be only one file in secretKeysDir and sigKeyDir
        self.publicKeysDir = None
        self.secretKeysDir = None
        self.verifKeyDir = None
        self.sigKeyDir = None

        self.signer = None
        self.verifiers = {}

        self.setupDirs()
        self.setupOwnKeysIfNeeded()
        self.setupSigning()

        # self.poller = test.asyncio.Poller()

        self.restricted = restricted

        self.ctx = None  # type: Context
        self.listener = None
        self.auth = None

        # Each remote is identified uniquely by the name
        self._remotes = {}  # type: Dict[str, Remote]

        self.remotesByKeys = {}

        # Indicates if this stack will maintain any remotes or will
        # communicate simply to listeners. Used in ClientZStack
        self.onlyListener = onlyListener
        self.peersWithoutRemotes = set()

        self._conns = set()  # type: Set[str]

        self.rxMsgs = deque()
        self._created = time.perf_counter()

    @property
    def remotes(self):
        return self._remotes

    @property
    def created(self):
        return self._created

    @property
    @abstractmethod
    def name(self):
        return self._name

    @staticmethod
    def isRemoteConnected(r) -> bool:
        return r.isConnected

    def removeRemote(self, remote: Remote, clear=True):
        """
        Currently not using clear
        """
        name = remote.name
        pkey = remote.publicKey
        vkey = remote.verKey
        if name in self.remotes:
            self.remotes.pop(name)
            self.remotesByKeys.pop(pkey, None)
            self.verifiers.pop(vkey, None)
        else:
            logger.warning('No remote named {} present')

    @staticmethod
    def initLocalKeys(name, baseDir, sigseed, override=False):
        sDir = os.path.join(baseDir, '__sDir')
        eDir = os.path.join(baseDir, '__eDir')
        os.makedirs(sDir, exist_ok=True)
        os.makedirs(eDir, exist_ok=True)
        (public_key, secret_key), (verif_key, sig_key) = createEncAndSigKeys(eDir,
                                                                             sDir,
                                                                             name,
                                                                             seed=sigseed)

        homeDir = ZStack.homeDirPath(baseDir, name)
        verifDirPath = ZStack.verifDirPath(homeDir)
        sigDirPath = ZStack.sigDirPath(homeDir)
        secretDirPath = ZStack.secretDirPath(homeDir)
        pubDirPath = ZStack.publicDirPath(homeDir)
        for d in (homeDir, verifDirPath, sigDirPath, secretDirPath, pubDirPath):
            os.makedirs(d, exist_ok=True)

        moveKeyFilesToCorrectLocations(sDir, verifDirPath, sigDirPath)
        moveKeyFilesToCorrectLocations(eDir, pubDirPath, secretDirPath)

        shutil.rmtree(sDir)
        shutil.rmtree(eDir)
        return hexlify(public_key).decode(), hexlify(verif_key).decode()

    @staticmethod
    def initRemoteKeys(name, remoteName, baseDir, verkey, override=False):
        homeDir = ZStack.homeDirPath(baseDir, name)
        verifDirPath = ZStack.verifDirPath(homeDir)
        pubDirPath = ZStack.publicDirPath(homeDir)
        for d in (homeDir, verifDirPath, pubDirPath):
            os.makedirs(d, exist_ok=True)

        if isHex(verkey):
            verkey = unhexlify(verkey)

        createCertsFromKeys(verifDirPath, remoteName, z85.encode(verkey))
        public_key = ed25519PkToCurve25519(verkey)
        createCertsFromKeys(pubDirPath, remoteName, z85.encode(public_key))

    def onHostAddressChanged(self):
        # we don't store remote data like ip, port, domain name, etc, so nothing to do here
        pass

    @staticmethod
    def areKeysSetup(name, baseDir):
        homeDir = ZStack.homeDirPath(baseDir, name)
        verifDirPath = ZStack.verifDirPath(homeDir)
        pubDirPath = ZStack.publicDirPath(homeDir)
        sigDirPath = ZStack.sigDirPath(homeDir)
        secretDirPath = ZStack.secretDirPath(homeDir)
        for d in (verifDirPath, pubDirPath):
            if not os.path.isfile(os.path.join(d, '{}.key'.format(name))):
                return False
        for d in (sigDirPath, secretDirPath):
            if not os.path.isfile(os.path.join(d, '{}.key_secret'.format(name))):
                return False
        return True

    @staticmethod
    def keyDirNames():
        return ZStack.PublicKeyDirName, ZStack.PrivateKeyDirName, \
               ZStack.VerifKeyDirName, ZStack.SigKeyDirName

    @staticmethod
    def getHaFromLocal(name, basedirpath):
        return None

    def __repr__(self):
        return self.name

    @staticmethod
    def homeDirPath(baseDirPath, name):
        return os.path.join(baseDirPath, name)

    @staticmethod
    def publicDirPath(homeDirPath):
        return os.path.join(homeDirPath, ZStack.PublicKeyDirName)

    @staticmethod
    def secretDirPath(homeDirPath):
        return os.path.join(homeDirPath, ZStack.PrivateKeyDirName)

    @staticmethod
    def verifDirPath(homeDirPath):
        return os.path.join(homeDirPath, ZStack.VerifKeyDirName)

    @staticmethod
    def sigDirPath(homeDirPath):
        return os.path.join(homeDirPath, ZStack.SigKeyDirName)

    @staticmethod
    def learnKeysFromOthers(baseDir, name, others):
        homeDir = ZStack.homeDirPath(baseDir, name)
        verifDirPath = ZStack.verifDirPath(homeDir)
        pubDirPath = ZStack.publicDirPath(homeDir)
        for d in (homeDir, verifDirPath, pubDirPath):
            os.makedirs(d, exist_ok=True)

        for other in others:
            createCertsFromKeys(verifDirPath, other.name, other.verKey)
            createCertsFromKeys(pubDirPath, other.name, other.publicKey)

    def tellKeysToOthers(self, others):
        for other in others:
            createCertsFromKeys(other.verifKeyDir, self.name, self.verKey)
            createCertsFromKeys(other.publicKeysDir, self.name, self.publicKey)

    def setupDirs(self):
        self.homeDir = self.homeDirPath(self.basedirpath, self.name)
        self.publicKeysDir = self.publicDirPath(self.homeDir)
        self.secretKeysDir = self.secretDirPath(self.homeDir)
        self.verifKeyDir = self.verifDirPath(self.homeDir)
        self.sigKeyDir = self.sigDirPath(self.homeDir)

        for d in (self.homeDir, self.publicKeysDir, self.secretKeysDir,
                  self.verifKeyDir, self.sigKeyDir):
            os.makedirs(d, exist_ok=True)

    def setupOwnKeysIfNeeded(self):
        if not os.listdir(self.sigKeyDir):
            # If signing keys are not present, secret (private keys) should
            # not be present since they should be converted keys.
            assert not os.listdir(self.secretKeysDir)
            # Seed should be present
            assert self.seed, 'Keys are not setup for {}'.format(self)
            logger.info("Signing and Encryption keys were not found for {}. "
                        "Creating them now".format(self),
                        extra={"cli": False})
            tdirS = os.path.join(self.homeDir, '__skeys__')
            tdirE = os.path.join(self.homeDir, '__ekeys__')
            os.makedirs(tdirS, exist_ok=True)
            os.makedirs(tdirE, exist_ok=True)
            createEncAndSigKeys(tdirE, tdirS, self.name, self.seed)
            moveKeyFilesToCorrectLocations(tdirE, self.publicKeysDir,
                                           self.secretKeysDir)
            moveKeyFilesToCorrectLocations(tdirS, self.verifKeyDir,
                                           self.sigKeyDir)
            shutil.rmtree(tdirE)
            shutil.rmtree(tdirS)

    def setupAuth(self, restricted=True, force=False):
        if self.auth and not force:
            raise RuntimeError('Listener already setup')
        location = self.publicKeysDir if restricted else zmq.auth.CURVE_ALLOW_ANY
        # self.auth = AsyncioAuthenticator(self.ctx)
        self.auth = MultiZapAuthenticator(self.ctx)
        self.auth.start()
        self.auth.allow('0.0.0.0')
        self.auth.configure_curve(domain='*', location=location)

    def teardownAuth(self):
        if self.auth:
            self.auth.stop()

    def setupSigning(self):
        # Setup its signer from the signing key stored at disk and for all
        # verification keys stored at disk, add Verifier
        _, sk = self.selfSigKeys
        self.signer = Signer(z85.decode(sk))
        for vk in self.getAllVerKeys():
            self.addVerifier(vk)

    def addVerifier(self, verkey):
        self.verifiers[verkey] = Verifier(z85.decode(verkey))

    def start(self, restricted=None, reSetupAuth=True):
        # self.ctx = test.asyncio.Context.instance()
        self.ctx = zmq.Context.instance()
        if self.MAX_SOCKETS:
            self.ctx.MAX_SOCKETS = self.MAX_SOCKETS
        restricted = self.restricted if restricted is None else restricted
        logger.info('{} starting with restricted as {} and reSetupAuth '
                    'as {}'.format(self, restricted, reSetupAuth),
                    extra={"cli": False, "demo": False})
        self.setupAuth(restricted, force=reSetupAuth)
        self.open()

    def stop(self):
        if self.opened:
            logger.info('stack {} closing its listener'.format(self),
                        extra={"cli": False, "demo": False})
            self.close()
        self.teardownAuth()
        logger.info("stack {} stopped".format(self),
                    extra={"cli": False, "demo": False})

    @property
    def opened(self):
        return self.listener is not None

    def open(self):
        # noinspection PyUnresolvedReferences
        self.listener = self.ctx.socket(zmq.ROUTER)
        # noinspection PyUnresolvedReferences
        # self.poller.register(self.listener, test.POLLIN)
        public, secret = self.selfEncKeys
        self.listener.curve_secretkey = secret
        self.listener.curve_publickey = public
        self.listener.curve_server = True
        self.listener.identity = self.publicKey
        logger.debug('{} will bind its listener at {}'.format(self, self.ha[1]))
        self.listener.setsockopt(zmq.TCP_KEEPALIVE, 1)
        self.listener.setsockopt(zmq.TCP_KEEPALIVE_INTVL, 1000)
        self.listener.bind(
            'tcp://*:{}'.format(self.ha[1]))

    def close(self):
        self.listener.unbind(self.listener.LAST_ENDPOINT)
        self.listener.close(linger=0)
        self.listener = None
        logger.debug('{} starting to disconnect remotes'.format(self))
        for r in self.remotes.values():
            r.disconnect()
            self.remotesByKeys.pop(r.publicKey, None)

        self._remotes = {}
        if self.remotesByKeys:
            logger.warning('{} found remotes that were only in remotesByKeys and '
                        'not in remotes. This is suspicious')
            for r in self.remotesByKeys.values():
                r.disconnect()
            self.remotesByKeys = {}
        self._conns = set()

    @property
    def selfEncKeys(self):
        serverSecretFile = os.path.join(self.secretKeysDir,
                                        "{}.key_secret".format(self.name))
        return zmq.auth.load_certificate(serverSecretFile)

    @property
    def selfSigKeys(self):
        serverSecretFile = os.path.join(self.sigKeyDir,
                                        "{}.key_secret".format(self.name))
        return zmq.auth.load_certificate(serverSecretFile)

    @property
    def isRestricted(self):
        return not self.auth.allow_any if self.auth is not None \
            else self.restricted

    @property
    def isKeySharing(self):
        # TODO: Change name after removing test
        return not self.isRestricted

    def isConnectedTo(self, name: str = None, ha: Tuple = None):
        if self.onlyListener:
            return self.hasRemote(name)
        return super().isConnectedTo(name, ha)

    def hasRemote(self, name):
        if self.onlyListener:
            if isinstance(name, str):
                name = name.encode()
            if name in self.peersWithoutRemotes:
                return True
        return super().hasRemote(name)

    def removeRemoteByName(self, name: str):
        if self.onlyListener:
            if name in self.peersWithoutRemotes:
                self.peersWithoutRemotes.remove(name)
                return True
        else:
            return super().removeRemoteByName(name)

    def getHa(self, name):
        # Return HA as None when its a `peersWithoutRemote`
        if self.onlyListener:
            if isinstance(name, str):
                name = name.encode()
            if name in self.peersWithoutRemotes:
                return None
        return super().getHa(name)

    async def service(self, limit=None) -> int:
        """
        Service `limit` number of received messages in this stack.

        :param limit: the maximum number of messages to be processed. If None,
        processes all of the messages in rxMsgs.
        :return: the number of messages processed.
        """
        if self.listener:
            await self._serviceStack(self.age)
        else:
            logger.debug("{} is stopped".format(self))

        r = len(self.rxMsgs)
        if r > 0:
            pracLimit = limit if limit else sys.maxsize
            return self.processReceived(pracLimit)
        return 0

    def _verifyAndAppend(self, msg, ident):
        # if self.verify(msg, ident):
        #     self.rxMsgs.append((msg[:-self.sigLen].decode(), ident))
        # else:
        #     logger.error('{} got error while '
        #                  'verifying message {} from {}'
        #                  .format(self, msg, ident))
        try:
            decoded = msg.decode()
        except UnicodeDecodeError as ex:
            logger.error('{} got exception while decoding {} to utf-8: {}'
                         .format(self, msg, ex))
            return False
        self.rxMsgs.append((decoded, ident))
        return True

    def _receiveFromListener(self, quota) -> int:
        """
        Receives messages from listener
        :param quota: number of messages to receive
        :return: number of received messages
        """
        assert quota
        i = 0
        while i < quota:
            try:
                ident, msg = self.listener.recv_multipart(flags=zmq.NOBLOCK)
                if not msg:
                    # Router probing sends empty message on connection
                    continue
                i += 1
                if self.onlyListener and ident not in self.remotesByKeys:
                    self.peersWithoutRemotes.add(ident)
                self._verifyAndAppend(msg, ident)
            except zmq.Again:
                break
        if i > 0:
            logger.trace('{} got {} messages through listener'.
                         format(self, i))
        return i

    def _receiveFromRemotes(self, quotaPerRemote) -> int:
        """
        Receives messages from remotes
        :param quotaPerRemote: number of messages to receive from one remote
        :return: number of received messages
        """

        assert quotaPerRemote
        totalReceived = 0
        for ident, remote in self.remotesByKeys.items():
            if not remote.socket:
                continue
            i = 0
            sock = remote.socket
            while i < quotaPerRemote:
                try:
                    msg, = sock.recv_multipart(flags=zmq.NOBLOCK)
                    if not msg:
                        # Router probing sends empty message on connection
                        continue
                    i += 1
                    self._verifyAndAppend(msg, ident)
                except zmq.Again:
                    break
            if i > 0:
                logger.trace('{} got {} messages through remote {}'.
                             format(self, i, remote))
            totalReceived += i
        return totalReceived

    async def _serviceStack(self, age):
        # TODO: age is unused
        self._receiveFromListener(quota=self.listenerQuota)
        self._receiveFromRemotes(quotaPerRemote=self.remoteQuota)
        return len(self.rxMsgs)

    def processReceived(self, limit):

        if limit <= 0:
            return 0

        for x in range(limit):
            try:
                msg, ident = self.rxMsgs.popleft()

                frm = self.remotesByKeys[ident].name \
                    if ident in self.remotesByKeys else ident

                r = self.handlePingPong(msg, frm, ident)
                if r:
                    continue

                try:
                    msg = self.deserializeMsg(msg)
                except Exception as e:
                    logger.error('Error {} while converting message {} '
                                 'to JSON from {}'.format(e, msg, ident))
                    continue

                msg = self.doProcessReceived(msg, frm, ident)
                if msg:
                    self.msgHandler((msg, frm))
            except IndexError:
                break
        return x + 1

    def handlePingPong(self, msg, frm, ident):
        if msg in (self.pingMessage, self.pongMessage):
            if msg == self.pingMessage:
                logger.debug('{} got ping from {}'.format(self, frm))
                self.sendPingPong(frm, is_ping=False)

            if msg == self.pongMessage:
                if ident in self.remotesByKeys:
                    self.remotesByKeys[ident].setConnected()
                logger.debug('{} got pong from {}'.format(self, frm))
            return True
        return False

    @abstractmethod
    def doProcessReceived(self, msg, frm, ident):
        return msg

    def connect(self,
                name=None,
                remoteId=None,
                ha=None,
                verKeyRaw=None,
                publicKeyRaw=None):
        """
        Connect to the node specified by name.
        """
        if not name:
            raise ValueError('Remote name should be specified')

        if name in self.remotes:
            remote = self.remotes[name]
        else:
            publicKey = z85.encode(publicKeyRaw) if publicKeyRaw else self.getPublicKey(name)
            verKey = z85.encode(verKeyRaw) if verKeyRaw else self.getVerKey(name)
            if not ha or not publicKey or (self.isRestricted and not verKey):
                raise ValueError('{} doesnt have enough info to connect. '
                                 'Need ha, public key and verkey. {} {} {}'.
                                 format(name, ha, verKey, publicKey))
            remote = self.addRemote(name, ha, verKey, publicKey)

        public, secret = self.selfEncKeys
        remote.connect(self.ctx, public, secret)

        logger.info("{} looking for {} at {}:{}".
                    format(self, name or remote.name, *remote.ha),
                    extra={"cli": "PLAIN", "tags": ["node-looking"]})

        # This should be scheduled as an async task
        self.sendPingPong(remote, is_ping=True)
        return remote.uid

    def reconnectRemote(self, remote):
        """
        Disconnect remote and connect to it again        
        
        :param remote: instance of Remote from self.remotes
        :param remoteName: name of remote
        :return: 
        """
        assert remote
        logger.debug('{} reconnecting to {}'.format(self, remote))
        public, secret = self.selfEncKeys
        remote.disconnect()
        remote.connect(self.ctx, public, secret)
        self.sendPingPong(remote, is_ping=True)

    def reconnectRemoteWithName(self, remoteName):
        assert remoteName
        assert remoteName in self.remotes
        self.reconnectRemote(self.remotes[remoteName])

    def disconnectByName(self, name: str):
        assert name
        remote = self.remotes.get(name)
        if not remote:
            logger.warning('{} did not find any remote '
                           'by name {} to disconnect'
                           .format(self, name))
            return None
        remote.disconnect()
        return remote

    def addRemote(self, name, ha, remoteVerkey, remotePublicKey):
        remote = Remote(name, ha, remoteVerkey, remotePublicKey)
        self.remotes[name] = remote
        # TODO: Use weakref to remote below instead
        self.remotesByKeys[remotePublicKey] = remote
        if remoteVerkey:
            self.addVerifier(remoteVerkey)
        else:
            logger.debug('{} adding a remote {}({}) without a verkey'.
                         format(self, name, ha))
        return remote

    def sendPingPong(self, remote: Union[str, Remote], is_ping=True):
        msg = self.pingMessage if is_ping else self.pongMessage
        action = 'ping' if is_ping else 'pong'
        name = remote if isinstance(remote, (str, bytes)) else remote.name
        r = self.send(msg, name)
        if r is True:
            logger.debug('{} {}ed {}'.format(self.name, action, name))
        elif r is False:
            # TODO: This fails the first time as socket is not established,
            # need to make it retriable
            logger.info('{} failed to {} {}'.
                        format(self.name, action, name),
                        extra={"cli": False})
        elif r is None:
            logger.debug('{} will be sending in batch'.format(self))
        else:
            logger.warn('{} got an unexpected return value {} while sending'.
                        format(self, r))
        return r

    def send(self, msg: Any, remoteName: str = None, ha=None):
        if self.onlyListener:
            return self.transmitThroughListener(msg, remoteName)
        else:
            if remoteName is None:
                r = []
                # Serializing beforehand since to avoid serializing for each
                # remote
                msg = self.serializeMsg(msg)
                for uid in self.remotes:
                    r.append(self.transmit(msg, uid, serialized=True))
                return all(r)
            else:
                return self.transmit(msg, remoteName)

    def transmit(self, msg, uid, timeout=None, serialized=False):
        remote = self.remotes.get(uid)
        if not remote:
            logger.debug("Remote {} does not exist!".format(uid))
            return False
        socket = remote.socket
        if not socket:
            logger.warning('{} has uninitialised socket '
                           'for remote {}'.format(self, uid))
            return False
        try:
            msg = self.serializeMsg(msg) if not serialized else msg
            # socket.send(self.signedMsg(msg), flags=zmq.NOBLOCK)
            socket.send(msg, flags=zmq.NOBLOCK)
            logger.debug('{} transmitting message {} to {}'
                        .format(self, msg, uid))
            if not remote.isConnected and msg not in self.healthMessages:
                logger.warning('Remote {} is not connected - '
                               'message will not be sent immediately.'
                               'If this problem does not resolve itself - '
                               'check your firewall settings'.format(uid))
            return True
        except zmq.Again:
            logger.info('{} could not transmit message to {}'
                        .format(self, uid))
        return False

    def transmitThroughListener(self, msg, ident):
        if isinstance(ident, str):
            ident = ident.encode()
        if ident not in self.peersWithoutRemotes:
            logger.debug('{} not sending message {} to {}'.
                         format(self, msg, ident))
            logger.debug("This is a temporary workaround for not being able to "
                         "disconnect a ROUTER's remote")
            return False
        msg = self.serializeMsg(msg)
        try:
            # noinspection PyUnresolvedReferences
            # self.listener.send_multipart([ident, self.signedMsg(msg)],
            #                              flags=zmq.NOBLOCK)
            self.listener.send_multipart([ident, msg], flags=zmq.NOBLOCK)
            return True
        except zmq.Again:
            return False
        except Exception as e:
            logger.error('{} got error {} while sending through listener to {}'.
                         format(self, e, ident))

    @staticmethod
    def serializeMsg(msg):
        if isinstance(msg, Mapping):
            msg = json.dumps(msg)
        if isinstance(msg, str):
            msg = msg.encode()
        assert isinstance(msg, bytes)
        return msg

    @staticmethod
    def deserializeMsg(msg):
        if isinstance(msg, bytes):
            msg = msg.decode()
        msg = json.loads(msg)
        return msg

    def signedMsg(self, msg: bytes, signer: Signer=None):
        sig = self.signer.signature(msg)
        return msg + sig

    def verify(self, msg, by):
        if self.isKeySharing:
            return True
        if by not in self.remotesByKeys:
            return False
        verKey = self.remotesByKeys[by].verKey
        r = self.verifiers[verKey].verify(msg[-self.sigLen:], msg[:-self.sigLen])
        return r

    @staticmethod
    def loadPubKeyFromDisk(directory, name):
        filePath = os.path.join(directory,
                                "{}.key".format(name))
        try:
            public, _ = zmq.auth.load_certificate(filePath)
            return public
        except (ValueError, IOError) as ex:
            raise KeyError from ex

    @staticmethod
    def loadSecKeyFromDisk(directory, name):
        filePath = os.path.join(directory,
                                "{}.key_secret".format(name))
        try:
            _, secret = zmq.auth.load_certificate(filePath)
            return secret
        except (ValueError, IOError) as ex:
            raise KeyError from ex

    @property
    def publicKey(self):
        return self.getPublicKey(self.name)

    @property
    def publicKeyRaw(self):
        return z85.decode(self.publicKey)

    @property
    def pubhex(self):
        return hexlify(z85.decode(self.publicKey))

    def getPublicKey(self, name):
        try:
            return self.loadPubKeyFromDisk(self.publicKeysDir, name)
        except KeyError:
            raise PublicKeyNotFoundOnDisk(self.name, name)

    @property
    def verKey(self):
        return self.getVerKey(self.name)

    @property
    def verKeyRaw(self):
        if self.verKey:
            return z85.decode(self.verKey)
        return None

    @property
    def verhex(self):
        if self.verKey:
            return hexlify(z85.decode(self.verKey))
        return None

    def getVerKey(self, name):
        try:
            return self.loadPubKeyFromDisk(self.verifKeyDir, name)
        except KeyError:
            if self.isRestricted:
                raise VerKeyNotFoundOnDisk(self.name, name)
            return None

    @property
    def sigKey(self):
        return self.loadSecKeyFromDisk(self.sigKeyDir, self.name)

    # TODO: Change name to sighex after removing test
    @property
    def keyhex(self):
        return hexlify(z85.decode(self.sigKey))

    @property
    def priKey(self):
        return self.loadSecKeyFromDisk(self.secretKeysDir, self.name)

    @property
    def prihex(self):
        return hexlify(z85.decode(self.priKey))

    def getAllVerKeys(self):
        keys = []
        for key_file in os.listdir(self.verifKeyDir):
            if key_file.endswith(".key"):
                serverVerifFile = os.path.join(self.verifKeyDir,
                                               key_file)
                serverPublic, _ = zmq.auth.load_certificate(serverVerifFile)
                keys.append(serverPublic)
        return keys

    def setRestricted(self, restricted: bool):
        if self.isRestricted != restricted:
            logger.debug('{} setting restricted to {}'.
                         format(self, restricted))
            self.stop()

            # TODO: REMOVE, it will make code slow, only doing to allow the
            # socket to become available again
            time.sleep(1)

            self.start(restricted, reSetupAuth=True)

    def _safeRemove(self, filePath):
        try:
            os.remove(filePath)
        except Exception as ex:
            logger.info('{} could delete file {} due to {}'.
                        format(self, filePath, ex))

    def clearLocalRoleKeep(self):
        for d in (self.secretKeysDir, self.sigKeyDir):
            filePath = os.path.join(d, "{}.key_secret".format(self.name))
            self._safeRemove(filePath)

        for d in (self.publicKeysDir, self.verifKeyDir):
            filePath = os.path.join(d, "{}.key".format(self.name))
            self._safeRemove(filePath)

    def clearRemoteRoleKeeps(self):
        for d in (self.secretKeysDir, self.sigKeyDir):
            for key_file in os.listdir(d):
                if key_file != '{}.key_secret'.format(self.name):
                    self._safeRemove(os.path.join(d, key_file))

        for d in (self.publicKeysDir, self.verifKeyDir):
            for key_file in os.listdir(d):
                if key_file != '{}.key'.format(self.name):
                    self._safeRemove(os.path.join(d, key_file))

    def clearAllDir(self):
        shutil.rmtree(self.homeDir)

    # TODO: Members below are just for the time till RAET replacement is
    # complete, they need to be removed then.
    @property
    def nameRemotes(self):
        logger.debug('{} proxy method used on {}'.
                    format(inspect.stack()[0][3], self))
        return self.remotes

    @property
    def keep(self):
        logger.debug('{} proxy method used on {}'.
                    format(inspect.stack()[0][3], self))
        if not hasattr(self, '_keep'):
            self._keep = DummyKeep(self)
        return self._keep

    def clearLocalKeep(self):
        pass

    def clearRemoteKeeps(self):
        pass


class DummyKeep:
    def __init__(self, stack, *args, **kwargs):
        self.stack = stack
        self._auto = 2 if stack.isKeySharing else 0

    @property
    def auto(self):
        logger.debug('{} proxy method used on {}'.
                    format(inspect.stack()[0][3], self))
        return self._auto

    @auto.setter
    def auto(self, mode):
        logger.debug('{} proxy method used on {}'.
                    format(inspect.stack()[0][3], self))
        # AutoMode.once whose value is 1 is not used os dont care
        if mode != self._auto:
            if mode == 2:
                self.stack.setRestricted(False)
            if mode == 0:
                self.stack.setRestricted(True)


class SimpleZStack(ZStack):

    def __init__(self,
                 stackParams: Dict,
                 msgHandler: Callable,
                 seed=None,
                 onlyListener=False,
                 sighex: str=None,
                 listenerQuota=DEFAULT_LISTENER_QUOTA,
                 remoteQuota=DEFAULT_REMOTE_QUOTA):

        # TODO: sighex is unused as of now, remove once test is removed or
        # maybe use sighex to generate all keys, DECISION DEFERRED

        self.stackParams = stackParams
        self.msgHandler = msgHandler

        # TODO: Ignoring `main` param as of now which determines
        # if the stack will have a listener socket or not.
        name = stackParams['name']
        ha = stackParams['ha']
        basedirpath = stackParams['basedirpath']

        auto = stackParams.pop('auth_mode', None)
        restricted = auto != AuthMode.ALLOW_ANY.value
        super().__init__(name,
                         ha,
                         basedirpath,
                         msgHandler=self.msgHandler,
                         restricted=restricted,
                         seed=seed,
                         onlyListener=onlyListener,
                         listenerQuota=listenerQuota,
                         remoteQuota=remoteQuota)


class KITZStack(SimpleZStack, KITNetworkInterface):
    # ZStack which maintains connections mentioned in its registry

    RETRY_TIMEOUT_NOT_RESTRICTED = 6
    RETRY_TIMEOUT_RESTRICTED = 15
    MAX_RECONNECT_RETRY_ON_SAME_SOCKET = 1

    def __init__(self,
                 stackParams: dict,
                 msgHandler: Callable,
                 registry: Dict[str, HA],
                 seed=None,
                 sighex: str = None,
                 listenerQuota=DEFAULT_LISTENER_QUOTA,
                 remoteQuota=DEFAULT_REMOTE_QUOTA):

        SimpleZStack.__init__(self,
                              stackParams,
                              msgHandler,
                              seed=seed,
                              sighex=sighex,
                              listenerQuota=listenerQuota,
                              remoteQuota=remoteQuota)

        KITNetworkInterface.__init__(self,
                                     registry=registry)

        self._retry_connect = {}

    def maintainConnections(self, force=False):
        """
        Ensure appropriate connections.

        """
        now = time.perf_counter()
        if now < self.nextCheck and not force:
            return False
        self.nextCheck = now + (self.RETRY_TIMEOUT_NOT_RESTRICTED
                                if self.isKeySharing
                                else self.RETRY_TIMEOUT_RESTRICTED)
        missing = self.connectToMissing()
        self.retryDisconnected(exclude=missing)
        logger.debug("{} next check for retries in {:.2f} seconds"
                     .format(self, self.nextCheck - now))
        return True

    def reconcileNodeReg(self) -> set:
        """
        Check whether registry contains some addresses 
        that were never connected to
        
        :return: 
        """

        matches = set()
        for name, remote in self.remotes.items():
            if name not in self.registry:
                continue
            if self.sameAddr(remote.ha, self.registry[name]):
                matches.add(name)
                logger.debug("{} matched remote {} {}".
                             format(self, remote.uid, remote.ha))
        return self.registry.keys() - matches - {self.name}

    def retryDisconnected(self, exclude=None):
        exclude = exclude or {}
        for name, remote in self.remotes.items():
            if name in exclude or remote.isConnected:
                continue

            if not name in self._retry_connect:
                self._retry_connect[name] = 0

            if not remote.socket or self._retry_connect[name] >= KITZStack.MAX_RECONNECT_RETRY_ON_SAME_SOCKET:
                self._retry_connect.pop(name, None)
                self.reconnectRemote(remote)
            else:
                self._retry_connect[name] += 1
                self.sendPingPong(remote, is_ping=True)

    def connectToMissing(self) -> set:
        """
        Try to connect to the missing nodes
        """

        missing = self.reconcileNodeReg()
        if not missing:
            return missing

        logger.debug("{} found the following "
                     "missing connections: {}"
                     .format(self, ", ".join(missing)))

        for name in missing:
            try:
                self.connect(name, ha=self.registry[name])
            except ValueError as ex:
                logger.error('{} cannot connect to {} due to {}'
                             .format(self, name, ex))
        return missing

    async def service(self, limit=None):
        c = await super().service(limit)
        return c

