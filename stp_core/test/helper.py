import os

import logging

from stp_core.common.log import getlogger
from stp_core.loop.motor import Motor
from stp_core.network.keep_in_touch import KITNetworkInterface

logger = logging.getLogger()


def createTempDir(tmpdir_factory, counter):
    tempdir = os.path.join(tmpdir_factory.getbasetemp().strpath,
                           str(next(counter)))
    logger.debug("module-level temporary directory: {}".format(tempdir))
    return tempdir


class Printer:
    def __init__(self, name):
        self.name = name
        self.printeds = []

    def print(self, m):
        print('{} printing... {}'.format(self.name, m))
        self.printeds.append(m)


def chkPrinted(p, m):
    assert m in [_[0] for _ in p.printeds]


class SMotor(Motor):
    def __init__(self, stack):
        Motor.__init__(self)
        self.stack = stack

    async def prod(self, limit) -> int:
        c = await self.stack.service(limit)
        if isinstance(self.stack, KITNetworkInterface):
            self.stack.serviceLifecycle()
        return c

    def start(self, loop):
        self.stack.start()

    def stop(self):
        self.stack.stop()


def prepStacks(looper, *stacks, connect=True, useKeys=True):
    for stack in stacks:
        motor = SMotor(stack)
        looper.add(motor)
    if connect:
        connectStacks(stacks, useKeys)


def connectStacks(stacks, useKeys=True):
    for stack in stacks:
        for otherStack in stacks:
            if stack != otherStack:
                stack.connect(name=otherStack.name, ha=otherStack.ha,
                              verKey=otherStack.verKey if useKeys else None,
                              publicKey=otherStack.publicKey if useKeys else None)


def checkStacksConnected(stacks):
    for stack in stacks:
        for otherStack in stacks:
            if stack != otherStack:
                assert otherStack.name in stack.connecteds
                assert stack.name in otherStack.connecteds
