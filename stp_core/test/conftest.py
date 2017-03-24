import importlib
import inspect
import itertools
import json
import logging
import os
import re
from copy import copy
from functools import partial
from typing import Dict, Any

import pip
import pytest
from stp_core.common.log import getlogger
from stp_core.crypto.util import randomSeed
from stp_core.network.port_dispenser import genHa
from stp_core.test.helper import createTempDir
from stp_core.types import HA


logger = getlogger()




basePath = os.path.dirname(os.path.abspath(__file__))



@pytest.fixture(scope="session")
def counter():
    return itertools.count()


@pytest.fixture(scope='module')
def tdir(tmpdir_factory, counter):
    return createTempDir(tmpdir_factory, counter)

another_tdir = tdir


@pytest.fixture(scope='function')
def tdir_for_func(tmpdir_factory, counter):
    tempdir = os.path.join(tmpdir_factory.getbasetemp().strpath,
                           str(next(counter)))
    logging.debug("function-level temporary directory: {}".format(tempdir))
    return tempdir


