# This is the interface for adb
__author__ = 'liyc'
import subprocess

class ADBException(Exception):
    """
    Exception in ADB connection
    """
    pass

class ADB(object):
    """
    interface of ADB
    """
    def __init__(self, device_serial = None):
        self.args = ['adb']
        self.shell = None

        r = subprocess.check_output(['adb', 'devices']).split('\n')
        if not r[0].startswith("List of devices attached"):
            raise ADBException
        for line in r[1:]:
            if not line or line == '':
                continue


        if device_serial:
            self.args.append("-s %s" % device_serial)
