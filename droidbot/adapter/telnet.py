import logging
import threading


class TelnetException(Exception):
    """
    Exception in telnet connection
    """
    pass


class TelnetConsole(object):
    """
    interface of telnet console, see:
    http://developer.android.com/tools/devices/emulator.html
    """
    def __init__(self, device):
        """
        initiate a emulator console via telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('TelnetConsole')
        self.host = "localhost"
        self.port = 5554

        if device.serial and device.serial.startswith("emulator-"):
            device.type = 1
            self.host = "localhost"
            self.port = int(device.serial[9:])
        else:
            raise TelnetException()

        self.device = device
        self.console = None
        self.__lock__ = threading.Lock()
        from telnetlib import Telnet
        self.console = Telnet(self.host, self.port)
        if self.check_connectivity():
            self.logger.debug("telnet successfully initiated, the addr is (%s:%d)" % (self.host, self.port))
        else:
            raise TelnetException()

    def run_cmd(self, args):
        """
        run a command in emulator console
        :param args: arguments to be executed in telnet console
        :return:
        """
        if isinstance(args, list):
            cmd_line = " ".join(args)
        elif isinstance(args, str):
            cmd_line = args
        else:
            self.logger.warning("unsupported command format:" + args)
            return

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
        return r.endswith('OK')

    def check_connectivity(self):
        """
        check if console is connected
        :return: True for connected
        """
        try:
            self.run_cmd("help")
        except:
            return False
        return True

    def disconnect(self):
        """
        disconnect telnet
        """
        self.console.close()
        self.logger.debug("disconnected")
