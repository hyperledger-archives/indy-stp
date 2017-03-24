import os

import logging

from stp_core.common.log import getlogger

logger = logging.getLogger()


def createTempDir(tmpdir_factory, counter):
    tempdir = os.path.join(tmpdir_factory.getbasetemp().strpath,
                           str(next(counter)))
    logger.debug("module-level temporary directory: {}".format(tempdir))
    return tempdir
