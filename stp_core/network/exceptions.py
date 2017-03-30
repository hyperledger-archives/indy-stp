from typing import Sequence

class RemoteError(Exception):
    def __init__(self, remote):
        self.remote = remote


class RemoteNotFound(RemoteError):
    pass


class DuplicateRemotes(Exception):
    def __init__(self, remotes):
        msg = "Found remotes {}: {}". \
            format(len(remotes), [(r.name, r.ha) for r in remotes])
        super(DuplicateRemotes, self).__init__(msg)


class EndpointException(Exception):
    pass


class MissingEndpoint(EndpointException):
    def __init__(self):
        super().__init__('missing endpoint')


class InvalidEndpointIpAddress(EndpointException):
    def __init__(self, endpoint):
        super().__init__("invalid endpoint address: '{}'".format(endpoint))


class InvalidEndpointPort(EndpointException):
    def __init__(self, endpoint):
        super().__init__("invalid endpoint port: '{}'".format(endpoint))


class PortNotAvailable(OSError):
    def __init__(self, port):
        self.port = port
        super().__init__("port not available: {}".format(port))
