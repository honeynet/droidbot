import logging
import socket

from .adapter import Adapter


class JDWPException(Exception):
    """
    Exception in jdwp connection
    """
    pass


class JDWP(Adapter):
    """
    a connection with target app through JDWP.
    """
    def __init__(self, device=None):
        """
        initiate a jdwp connection.
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.host = "localhost"

        if device is None:
            from droidbot.device import Device
            device = Device()
        self.device = device
        self.port = self.device.get_random_port()

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False

    def connect(self):
        pass
        # TODO

    def check_connectivity(self):
        """
        check if droidbot app is connected
        :return: True for connected
        """
        if not self.connected:
            return False
        return True

    def disconnect(self):
        """
        disconnect jdwp
        """
        self.connected = False
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception as e:
                print(e)
        # TODO


if __name__ == "__main__":
    pass
