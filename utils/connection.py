# This is the interface for adb
__author__ = 'liyc'
import subprocess


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


class ADB(object):
    """
    interface of ADB
    send adb commands via this, see:
    http://developer.android.com/tools/help/adb.html
    """
    def __init__(self, device_serial = None):
        """
        initiate a ADB connection from serial no
        the serial no should be in output of `adb devices`
        :param device_serial: serial no of device
        :return:
        """
        self.args = ['adb']
        self.shell = None
        self.device_serial = device_serial
        r = subprocess.check_output(['adb', 'devices']).split('\n')
        if not r[0].startswith("List of devices attached"):
            raise ADBException

        online_devices = []
        for line in r[1:]:
            if not line:
                continue
            segs = line.split('\t')
            if len(segs) != 2:
                continue
            if segs[1] == "device":
                online_devices.append(segs[0])

        if not online_devices:
            raise ADBException

        if device_serial:
            if not device_serial in online_devices:
                raise ADBException
        else:
            self.device_serial = online_devices[0]

        self.args.append("-s")
        self.args.append(self.device_serial)

        if self.check_connectivity():
            print "adb successfully initiated, the device is %s" % self.device_serial
        else:
            raise ADBException

    def run_cmd(self, extra_args):
        """
        run an adb command and return the output
        :return: output of adb command
        """
        args = self.args
        args.append(extra_args)
        r = subprocess.check_output(args)
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
    def __init__(self, host = "localhost", port = 5554):
        """
        initiate a emulator console via telnet
        :param host: always be localhost
        :param port: port number of the emulator, default is 5554
        :return:
        """
        self.host = host
        self.port = 5554
        self.console = None
        from telnetlib import Telnet
        self.console = Telnet(self.host, self.port)

    def run_cmd(self, args):
        """
        run a command in emulator console
        :param args: arguments to be executed in telnet console
        :return:
        """