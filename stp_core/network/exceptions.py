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
