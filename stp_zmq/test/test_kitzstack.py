from copy import copy

from stp_core.loop.eventually import eventually
from stp_core.network.auth_mode import AuthMode
from stp_core.test.helper import Printer, prepStacks, \
    checkStacksConnected
from stp_zmq.test.helper import genKeys
from stp_zmq.zstack import KITZStack


def testKitZStacksConnected(registry, tdir, looper):
    genKeys(tdir, registry.keys())
    stacks = []
    for name, ha in registry.items():
        printer = Printer(name)
        stackParams = dict(name=name, ha=ha, basedirpath=tdir, auth_mode=AuthMode.RESTRICTED.value)
        reg = copy(registry)
        reg.pop(name)
        stack = KITZStack(stackParams, printer.print, reg)
        stacks.append(stack)

    prepStacks(looper, *stacks, connect=False, useKeys=True)
    looper.run(eventually(checkStacksConnected, stacks, retryWait=1,
                          timeout=5))
