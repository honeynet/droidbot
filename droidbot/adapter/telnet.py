import logging
import threading
from .adapter import Adapter


class TelnetException(Exception):
    """
    Exception in telnet connection
    """
    pass


class TelnetConsole(Adapter):
    """
    interface of telnet console, see:
    http://developer.android.com/tools/devices/emulator.html
    """
    def __init__(self, device=None, auth_token=None):
        """
        Initiate a emulator console via telnet.
        On some devices, an authentication token is required to use telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger(self.__class__.__name__)

        if device is None:
            from droidbot.device import Device
            device = Device()
        self.device = device
        self.auth_token = auth_token
        self.console = None
        self.__lock__ = threading.Lock()

    def connect(self):
        if self.device.serial and self.device.serial.startswith("emulator-"):
            host = "localhost"
            port = int(self.device.serial[9:])
            from telnetlib import Telnet
            self.console = Telnet(host, port)
            if self.auth_token is not None:
                self.run_cmd("auth %s" % self.auth_token)
            if self.check_connectivity():
                self.logger.debug("telnet successfully initiated, the port is %d" % port)
                return
        raise TelnetException()

    def run_cmd(self, args):
        """
        run a command in emulator console
        :param args: arguments to be executed in telnet console
        :return:
        """
        if self.console is None:
            self.logger.warning("telnet is not connected!")
            return None
        if isinstance(args, list):
            cmd_line = " ".join(args)
        elif isinstance(args, str):
            cmd_line = args
        else:
            self.logger.warning("unsupported command format:" + args)
            return None

        self.logger.debug('command:')
        self.logger.debug(cmd_line)

        cmd_line += '\n'

        self.__lock__.acquire()
        self.console.write(cmd_line)
        r = self.console.read_until('OK', 5)
        # eat the rest outputs
        self.console.read_until('NEVER MATCH', 1)
        self.__lock__.release()

        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def check_connectivity(self):
        """
        check if console is connected
        :return: True for connected
        """
        if self.console is None:
            return False
        try:
            self.run_cmd("help")
        except:
            return False
        return True

    def disconnect(self):
        """
        disconnect telnet
        """
        if self.console is not None:
            self.console.close()
        print("[CONNECTION] %s is disconnected" % self.__class__.__name__)
