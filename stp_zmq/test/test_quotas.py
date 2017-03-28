import json

from stp_core.crypto.util import randomSeed
from stp_core.network.port_dispenser import genHa
from stp_core.test.helper import Printer, prepStacks
from stp_zmq.test.helper import genKeys, makeHandler
from stp_zmq.zstack import ZStack


def testMessageQuota(tdir, looper):
    names = ['Alpha', 'Beta']
    genKeys(tdir, names)
    alphaP = Printer(names[0])
    receivedMessages = []
    betaMshHandler = makeHandler(receivedMessages)

    alpha = ZStack(names[0], ha=genHa(), basedirpath=tdir, msgHandler=alphaP.print,
                   restricted=True)
    beta = ZStack(names[1], ha=genHa(), basedirpath=tdir, msgHandler=betaMshHandler,
                  restricted=True, onlyListener=True)

    prepStacks(looper, alpha, beta, connect=True, useKeys=True)

    messages = []
    numMessages = 100 * beta.listenerQuota
    for i in range(numMessages):
        msg = json.dumps({'random': randomSeed().decode()}).encode()
        messages.append(json.loads(msg.decode()))
        alpha.send(msg, beta.name)

    looper.runFor(2)
    assert messages == receivedMessages
