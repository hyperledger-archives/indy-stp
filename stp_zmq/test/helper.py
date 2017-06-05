import os
import types
from distutils.dir_util import copy_tree

from stp_zmq.util import generate_certificates
from stp_zmq.zstack import ZStack


def genKeys(baseDir, names):
    generate_certificates(baseDir, *names, clean=True)
    for n in names:
        d = os.path.join(baseDir, n)
        os.makedirs(d, exist_ok=True)
        for kd in ZStack.keyDirNames():
            copy_tree(os.path.join(baseDir, kd), os.path.join(d, kd))

def patch_send_ping_counter(stack):
    stack.ping_count = 0
    origMethod = stack.sendPingPong

    def sendPingPongCounter(self, remote, is_ping=True):
        self.ping_count += 1
        return origMethod(remote, is_ping)

    stack.sendPingPong = types.MethodType(sendPingPongCounter, stack)
