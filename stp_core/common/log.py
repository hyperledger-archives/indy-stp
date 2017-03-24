import inspect
import logging
import os
import sys

from ioflo.base.consoling import getConsole, Console
from stp_core.common.logging.TimeAndSizeRotatingFileHandler import TimeAndSizeRotatingFileHandler
from stp_core.common.util import Singleton
from stp_core.util import getConfig

TRACE_LOG_LEVEL = 5
DISPLAY_LOG_LEVEL = 25

# TODO: move it to plenum-util repo


def getlogger(name: object = None) -> object:
    return Logger().getlogger(name)


class TestingHandler(logging.Handler):
    def __init__(self, tester):
        """
        Initialize the handler.
        """
        super().__init__()
        self.tester = tester

    def emit(self, record):
        """
        Captures a record.
        """
        self.tester(record)


class Logger(metaclass=Singleton):
    def __init__(self, config=None):
        # TODO: This should take directory
        self._config = config or getConfig()
        self._addTraceToLogging()

        self._handlers = {}
        self._format = logging.Formatter(fmt=self._config.logFormat,
                                         style=self._config.logFormatStyle)

        self._default_raet_verbosity = \
            getRAETLogLevelFromConfig("RAETLogLevel",
                                      Console.Wordage.terse,
                                      self._config)

        self._default_raet_log_file = \
            getRAETLogFilePath("RAETLogFilePath", self._config)

        self.enableStdLogging()

        self.setLogLevel(TRACE_LOG_LEVEL)

    @staticmethod
    def getlogger(name=None):
        if not name:
            curframe = inspect.currentframe()
            calframe = inspect.getouterframes(curframe, 2)
            name = inspect.getmodule(calframe[1][0]).__name__
        logger = logging.getLogger(name)
        return logger

    @staticmethod
    def setLogLevel(log_level):
        logging.root.setLevel(log_level)

    def setupRaet(self, raet_log_level=None, raet_log_file=None):
        console = getConsole()

        verbosity = raet_log_level \
            if raet_log_level is not None \
            else self._default_raet_verbosity
        file = raet_log_file or self._default_raet_log_file

        logging.info("Setting RAET log level {}".format(verbosity),
                     extra={"cli": False})

        console.reinit(verbosity=verbosity, path=file, flushy=True)

    def enableStdLogging(self):
        # only enable if CLI is not
        if 'cli' in self._handlers:
            raise RuntimeError('cannot configure STD logging '
                               'when CLI logging is enabled')
        new = logging.StreamHandler(sys.stdout)
        self._setHandler('std', new)

    def enableFileLogging(self, filename):
        d = os.path.dirname(filename)
        if not os.path.exists(d):
            os.makedirs(d)
        new = TimeAndSizeRotatingFileHandler(
            filename,
            when=self._config.logRotationWhen,
            interval=self._config.logRotationInterval,
            backupCount=self._config.logRotationBackupCount,
            utc=True,
            maxBytes=self._config.logRotationMaxBytes)
        self._setHandler('file', new)

    def _setHandler(self, typ: str, new_handler):
        if new_handler.formatter is None:
            new_handler.setFormatter(self._format)

        # assuming indempotence and removing old one first
        self._clearHandler(typ)

        self._handlers[typ] = new_handler
        logging.root.addHandler(new_handler)

    def _clearHandler(self, typ: str):
        old = self._handlers.get(typ)
        if old:
            logging.root.removeHandler(old)

    @staticmethod
    def _addTraceToLogging():
        logging.addLevelName(TRACE_LOG_LEVEL, "TRACE")

        def trace(self, message, *args, **kwargs):
            if self.isEnabledFor(TRACE_LOG_LEVEL):
                self._log(TRACE_LOG_LEVEL, message, args, **kwargs)

        logging.Logger.trace = trace


def getRAETLogLevelFromConfig(paramName, defaultValue, config):
    try:
        defaultVerbosity = config.__getattribute__(paramName)
        defaultVerbosity = Console.Wordage.__getattribute__(defaultVerbosity)
    except AttributeError:
        defaultVerbosity = defaultValue
        logging.debug("Ignoring RAET log level {} from config and using {} "
                      "instead".format(paramName, defaultValue))
    return defaultVerbosity


def getRAETLogFilePath(paramName, config):
    try:
        filePath = config.__getattribute__(paramName)
    except AttributeError:
        filePath = None
    return filePath


