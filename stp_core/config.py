import os

baseDir = os.getcwd()

# Log configuration
logRotationWhen = 'D'
logRotationInterval = 1
logRotationBackupCount = 10
logRotationMaxBytes = 100 * 1024 * 1024
logFormat = '{asctime:s} | {levelname:8s} | {filename:20s} ({lineno:d}) | {funcName:s} | {message:s}'
logFormatStyle='{'


RAETLogLevel = "terse"
RAETLogLevelCli = "mute"
RAETLogFilePath = os.path.join(os.path.expanduser(baseDir), "test.log")
RAETLogFilePathCli = None
RAETMessageTimeout = 60
