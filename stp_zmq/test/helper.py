import os
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

def makeHandler(receivedMessages):
    def handler(m):
        msg, sender = m
        receivedMessages.append(msg)
        print("Got message", msg)

    return handler
