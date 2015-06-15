# This is the interface for adb
__author__ = 'liyc'
import subprocess
import logging


class ADBException(Exception):
    """
    Exception in ADB connection
    """
    pass


class TelnetException(Exception):
    """
    Exception in telnet connection
    """
    pass


class MonkeyException(Exception):
    """
    Exception in monkeyrunner connection
    """
    pass

class ADB(object):
    """
    interface of ADB
    send adb commands via this, see:
    http://developer.android.com/tools/help/adb.html
    """
    def __init__(self, device):
        """
        initiate a ADB connection from serial no
        the serial no should be in output of `adb devices`
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('ADB')
        self.device = device
        self.args = ['adb']
        self.shell = None

        r = subprocess.check_output(['adb', 'devices']).split('\n')
        if not r[0].startswith("List of devices attached"):
            raise ADBException()

        online_devices = []
        for line in r[1:]:
            if not line:
                continue
            segments = line.split("\t")
            if len(segments) != 2:
                continue
            if segments[1] == "device":
                online_devices.append(segments[0])

        if not online_devices:
            raise ADBException()

        if device.serial:
            if not device.serial in online_devices:
                raise ADBException()
        else:
            device.serial = online_devices[0]

        self.args.append("-s")
        self.args.append(device.serial)

        if self.check_connectivity():
            self.logger.info("adb successfully initiated, the device is %s" % device.serial)
        else:
            raise ADBException()

    def run_cmd(self, extra_args):
        """
        run an adb command and return the output
        :return: output of adb command
        """
        args = [] + self.args
        if isinstance(extra_args, list):
            args += extra_args
        else:
            args.append(extra_args)
        self.logger.debug('command:')
        self.logger.debug(args)
        r = subprocess.check_output(args)
        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def check_connectivity(self):
        """
        check if adb is connected
        :return: True for connected
        """
        r = self.run_cmd("get-state")
        return r.startswith("device")


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
        from telnetlib import Telnet
        self.console = Telnet(self.host, self.port)
        if self.check_connectivity():
            self.logger.info("telnet successfully initiated, the addr is (%s:%d)" % (self.host, self.port))
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
        else:
            cmd_line = args
        self.logger.debug('command:')
        self.logger.debug(cmd_line)
        cmd_line += '\n'
        self.console.write(cmd_line)
        r = self.console.read_until('OK', 5)
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


class MonkeyRunner(object):
    """
    interface of monkey runner connection
    http://developer.android.com/tools/help/monkeyrunner_concepts.html
    """
    def __init__(self, device):
        """
        initiate a monkeyrunner shell
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('MonkeyRunner')
        self.console = subprocess.Popen('monkeyrunner', stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.run_cmd('from com.android.monkeyrunner import MonkeyRunner, MonkeyDevice')
        self.run_cmd('device=MonkeyRunner.waitForConnection(5,%s)' % device.serial)
        if self.check_connectivity():
            self.logger.info("monkeyrunner successfully initiated, the device is %s" % device.serial)
        else:
            raise MonkeyException()

    def run_cmd(self, args):
        """
        run a command via monkeyrunner
        :param args: arguments to be executed in monkeyrunner console
        :return:
        """
        if isinstance(args, list):
            cmd_line = " ".join(args)
        else:
            cmd_line = args
        self.logger.debug('command:')
        self.logger.debug(cmd_line)
        cmd_line += '\n'
        self.console.stdin.write(cmd_line)
        r=self.console.stdout.readline()
        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def check_connectivity(self):
        """
        check if console is connected
        :return: True for connected
        """
        try:
            self.run_cmd("r=device.getProperty(clock.millis)")
            (out, err) = self.run_cmd("print r")
            if err != None:
                return False
            segs = out.split('\n')
            if int(segs[0]) <= 0:
                return False
            if not segs[1].startswith('>>>'):
                return False
        except:
            return False
        return True