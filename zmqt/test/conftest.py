import asyncio

import pytest
# import zmqt.asyncio
from stp_core.common.temp_file_util import SafeTemporaryDirectory
from stp_core.loop.looper import Looper

from stp_core.network.port_dispenser import genHa


@pytest.fixture()
def registry():
    return {
        'Alpha': genHa(),
        'Beta': genHa(),
        'Gamma': genHa(),
        'Delta': genHa()
    }


# @pytest.fixture()
# def loop():
#     loop = zmqt.asyncio.ZMQEventLoop()
#     loop.set_debug(True)


@pytest.yield_fixture()
def tdirAndLooper():
    with SafeTemporaryDirectory() as td:
        with Looper(debug=True) as looper:
            yield td, looper


@pytest.fixture()
def tdir(tdirAndLooper):
    return tdirAndLooper[0]


@pytest.fixture()
def looper(tdirAndLooper):
    return tdirAndLooper[1]
