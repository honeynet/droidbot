import logging
import subprocess
import telnetlib
import time
from .adapter import Adapter


QEMU_START_DELAY = 60


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
    def __init__(self, hda, telnet_port, hostfwd_port, qemu_no_graphic):
        """
        initiate a QEMU connection
        :return:
        """
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger('QEMU')

        self.hda = hda
        self.domain = "localhost"
        self.telnet_port = telnet_port
        self.hostfwd_port = hostfwd_port
        self.qemu_no_graphic = qemu_no_graphic
        self.connected = False

    def set_up(self):
        # start qemu instance
        qemu_cmd = ["qemu-system-i386",
                    "-hda", self.hda,
                    "-smp", "cpus=4",
                    "-m", "2048",
                    "-machine", "q35",
                    "-monitor", "telnet:%s:%d,server,nowait" % \
                    (self.domain, self.telnet_port),
                    "-net", "nic,model=e1000",
                    "-net", "user,hostfwd=tcp::%d-:5555" % \
                    self.hostfwd_port,
                    "-enable-kvm"]
        if self.qemu_no_graphic:
            qemu_cmd.append("-nographic")
        self.logger.info(qemu_cmd)
        self.qemu_p = subprocess.Popen(qemu_cmd)
        self.pid = self.qemu_p.pid
        time.sleep(QEMU_START_DELAY)

    def utf8bytes(self, string):
        return bytes(string, encoding="utf-8")

    def connect(self, from_snapshot=False):
        # 1. Connect to QMP
        self.qemu_tel = telnetlib.Telnet(host=self.domain, port=self.telnet_port)
        self.logger.info(self.qemu_tel.read_until(self.utf8bytes("\r\n")))
        # 2. Recover adbd if from_snapshot
        if from_snapshot:
            self.send_command("stop")
            self.send_command("loadvm spawn")
            self.send_command("cont")

            self.send_keystrokes(["alt-f1"])
            self.send_keystrokes("killall")
            self.send_keystrokes(["spc"])
            self.send_keystrokes("adbd")
            self.send_keystrokes(["kp_enter"])
            self.send_keystrokes("adbd")
            self.send_keystrokes(["spc"])
            self.send_keystrokes("&")
            self.send_keystrokes(["kp_enter"])
            self.send_keystrokes(["alt-f7"])

            self.send_command("stop")
            self.send_command("delvm spawn")
            self.send_command("cont")

        # 3. Connect to ADB
        print(["adb", "connect", "%s:%s" % (self.domain, self.hostfwd_port)])
        p = subprocess.Popen(["adb", "connect", "%s:%s" % (self.domain, self.hostfwd_port)])
        p.wait()
        self.connected = True

    def send_command(self, command_str):
        """
        send command, then read result
        """
        self.qemu_tel.write(self.utf8bytes(command_str + "\r\n"))
        self.qemu_tel.read_until(self.utf8bytes("\r\n"))
        self.qemu_tel.read_until(self.utf8bytes("\r\n"))

    def send_keystrokes(self, keystrokes):
        for keystroke in keystrokes:
            self.send_command("sendkey %s" % keystroke)

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
                         8002, 4444, False)
    qemu_conn.set_up()
    qemu_conn.connect(from_snapshot=False)
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
