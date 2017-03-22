class RemoteError(Exception):
    def __init__(self, remote):
        self.remote = remote


class RemoteNotFound(RemoteError):
    pass
