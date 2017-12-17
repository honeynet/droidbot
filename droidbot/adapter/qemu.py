import logging
import socket
import subprocess
import time
import json
import telnetlib
import threading
from adapter import Adapter


QEMU_START_DELAY = 1

class QEMUConnException(Exception):
    """
    Exception in telnet connection
    """
    pass

class EOF(Exception):
    """
    Exception in telnet connection
    """
    pass

class QEMUConn(Adapter):
    """
    a connection with QEMU.
    """
    def __init__(self, hda_path, telnet_port, hostfwd_port):
        """
        initiate a QEMU connection
        :return:
        """
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('QEMU')

        self.hda_path = hda_path
        self.domain = "localhost"
        self.telnet_port = telnet_port
        self.hostfwd_port = hostfwd_port
        self.connected = False

    def set_up(self):
        # start qemu instance
        self.qemu_p = subprocess.Popen(["qemu-system-i386",
                                        "-hda", self.hda_path,
                                        "-smp", "cpus=4",
                                        "-m", "2048",
                                        "-machine", "q35",
                                        "-monitor", "telnet:%s:%d,server,nowait" % \
                                        (self.domain, self.telnet_port),
                                        "-net", "nic",
                                        "-net", "user,hostfwd=tcp::%d-:5555" % \
                                        self.hostfwd_port,
                                        "-enable-kvm"])
        self.pid = self.qemu_p.pid
        time.sleep(QEMU_START_DELAY)

    def connect(self):
        # 1. Connect to QMP
        self.qemu_tel = telnetlib.Telnet(host=self.domain, port=self.telnet_port)
        self.logger.info(self.qemu_tel.read_until("\r\n"))
        # 2. Connect to ADB
        r = subprocess.Popen(["adb", "connect", "%s:%s" % (self.domain, self.hostfwd_port)])
        self.connected = True

    def send_command(self, command_str):
        """
        send command, then read result
        """
        self.qemu_tel.write(command_str + "\r\n")
        self.qemu_tel.read_until("\r\n")
        self.qemu_tel.read_until("\r\n")

    def check_connectivity(self):
        """
        check if QEMU is connected
        :return: True for connected
        """
        return self.connected

    def disconnect(self):
        """
        disconnect telnet
        """
        self.qemu_tel.close()

    def tear_down(self):
        """
        stop QEMU instance
        """
        self.qemu_p.kill()

if __name__ == "__main__":
    qemu_conn = QEMUConn("/mnt/EXT_volume/lab_data/android_x86_qemu/droidmaster/android.img",
                         8002, 4444)
    qemu_conn.set_up()
    qemu_conn.connect()
    time.sleep(5)
    print("Start saving")
    qemu_conn.send_command("stop")
    qemu_conn.send_command("savevm test1")
    qemu_conn.send_command("cont")
    time.sleep(10)
    print("Start recovering")
    qemu_conn.send_command("loadvm test1")
    time.sleep(10)
    qemu_conn.send_command("delvm test1")
    qemu_conn.disconnect()
    qemu_conn.tear_down()
