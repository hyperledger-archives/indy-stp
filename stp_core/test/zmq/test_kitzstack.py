from copy import copy

from stp_core.loop.eventually import eventually
from stp_core.test.zmq.helper import genKeys, Printer, prepStacks, checkStacksConnected
from stp_core.zmq.zstack import KITZStack


def testKitZStacksConnected(registry, tdir, looper):
    genKeys(tdir, registry.keys())
    stacks = []
    for name, ha in registry.items():
        printer = Printer(name)
        stackParams = dict(name=name, ha=ha, basedirpath=tdir, auto=0)
        reg = copy(registry)
        reg.pop(name)
        stack = KITZStack(stackParams, printer.print, reg)
        stacks.append(stack)

    prepStacks(looper, *stacks, connect=False)
    looper.run(eventually(checkStacksConnected, stacks, retryWait=1, timeout=10))

