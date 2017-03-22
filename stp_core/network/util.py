import logging
import socket


def checkPortAvailable(ha):
    """Checks whether the given port is available"""
    # Not sure why OS would allow binding to one type and not other.
    # Checking for port available for TCP and UDP, this is done since
    # either RAET (UDP) or CurveZMQ(TCP) could have been used
    sockTypes = (socket.SOCK_DGRAM, socket.SOCK_STREAM)
    for typ in sockTypes:
        sock = socket.socket(socket.AF_INET, typ)
        try:
            sock.bind(ha)
        except BaseException as ex:
            logging.warning("Checked port availability for opening "
                            "as {} but address was already in use: {}".
                            format(typ, ha))
            raise ex
        finally:
            sock.close()
