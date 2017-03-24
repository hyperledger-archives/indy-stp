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
from stp_core.crypto.util import randomSeed
from stp_core.network.port_dispenser import genHa
from stp_core.test.helper import createTempDir
from stp_core.types import HA


logger = logging.getLogger()


basePath = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope='module')
def tdir(tmpdir_factory):
    return tmpdir_factory.mktemp('').strpath


@pytest.fixture(scope='function')
def tdir_for_func(tmpdir_factory):
    return tmpdir_factory.mktemp('').strpath

