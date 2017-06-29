import logging
import socket
import subprocess
import time
from datetime import datetime
from adapter import Adapter

MINICAP_REMOTE_ADDR = "localabstract:minicap"


class MinicapException(Exception):
    """
    Exception in minicap connection
    """
    pass


class Minicap(Adapter):
    """
    a connection with target device through minicap.
    """
    def __init__(self, device=None):
        """
        initiate a emulator console via telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('minicap')
        self.host = "localhost"
        self.port = 7335
        self.device = device
        self.remote_minicap_path = "/data/local/tmp/minicap-devel"

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = False
        self.minicap_process = None
        self.banner = None
        self.last_screen = None
        self.last_screen_time = None

        if self.device is None:
            from droidbot.device import Device
            self.device = Device()

    def set_up(self):
        device = self.device

        try:
            minicap_files = device.adb.shell("ls %s 2>/dev/null" % self.remote_minicap_path).split()
            if "minicap.so" in minicap_files and ("minicap" in minicap_files or "minicap-nopie" in minicap_files):
                self.logger.debug("minicap was already installed.")
                return
        except:
            pass

        if device is not None:
            # install minicap
            import pkg_resources
            local_minicap_path = pkg_resources.resource_filename("droidbot", "resources/minicap")
            try:
                device.adb.shell("mkdir %s 2>/dev/null" % self.remote_minicap_path)
            except Exception:
                pass
            abi = device.adb.get_property('ro.product.cpu.abi')
            sdk = device.get_sdk_version()
            if sdk >= 16:
                minicap_bin = "minicap"
            else:
                minicap_bin = "minicap-nopie"
            device.push_file(local_file="%s/libs/%s/%s" % (local_minicap_path, abi, minicap_bin),
                             remote_dir=self.remote_minicap_path)
            device.push_file(local_file="%s/jni/libs/android-%s/%s/minicap.so" % (local_minicap_path, sdk, abi),
                             remote_dir=self.remote_minicap_path)
            self.logger.debug("minicap installed.")

    def tear_down(self):
        try:
            self.device.adb.shell("rm -r %s" % self.remote_minicap_path)
        except Exception:
            pass

    def connect(self):
        device = self.device
        display = device.get_display_info(refresh=True)
        if 'width' not in display or 'height' not in display or 'orientation' not in display:
            self.logger.warning("Cannot get the size of current device.")
            return
        w = display['width']
        h = display['height']
        if w > h:
            temp = w
            w = h
            h = temp
        o = display['orientation'] * 90

        size_opt = "%dx%d@%dx%d/%d" % (w, h, w, h, o)
        start_minicap_cmd = "adb -s %s shell LD_LIBRARY_PATH=%s %s/minicap -P %s" % \
                            (device.serial, self.remote_minicap_path, self.remote_minicap_path, size_opt)
        self.logger.debug("starting minicap: " + start_minicap_cmd)
        self.minicap_process = subprocess.Popen(start_minicap_cmd.split(),
                                                stdin=subprocess.PIPE,
                                                stderr=subprocess.PIPE,
                                                stdout=subprocess.PIPE)
        # Wait 2 seconds for minicap starting
        time.sleep(2)
        self.logger.debug("minicap started.")

        try:
            # forward host port to remote port
            forward_cmd = "adb -s %s forward tcp:%d %s" % (device.serial, self.port, MINICAP_REMOTE_ADDR)
            subprocess.check_call(forward_cmd.split())
            self.sock.connect((self.host, self.port))
            import threading
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.start()
        except socket.error as ex:
            self.connected = False
            self.logger.warning(ex.message)
            raise MinicapException()

    def listen_messages(self):
        self.logger.debug("start listening minicap images ...")
        CHUNK_SIZE = 4096

        readBannerBytes = 0
        bannerLength = 2
        readFrameBytes = 0
        frameBodyLength = 0
        frameBody = bytearray()
        banner = {
            "version": 0,
            "length": 0,
            "pid": 0,
            "realWidth": 0,
            "realHeight": 0,
            "virtualWidth": 0,
            "virtualHeight": 0,
            "orientation": 0,
            "quirks": 0,
        }

        self.connected = True
        while self.connected:
            chunk = bytearray(self.sock.recv(CHUNK_SIZE))
            if not chunk:
                continue
            chunk_len = len(chunk)
            cursor = 0
            while cursor < chunk_len:
                if readBannerBytes < bannerLength:
                    if readBannerBytes == 0:
                        banner['version'] = chunk[cursor]
                    elif readBannerBytes == 1:
                        banner['length'] = bannerLength = chunk[cursor]
                    elif 2 <= readBannerBytes <= 5:
                        banner['pid'] += (chunk[cursor] << ((readBannerBytes - 2) * 8))
                    elif 6 <= readBannerBytes <= 9:
                        banner['realWidth'] += (chunk[cursor] << ((readBannerBytes - 6) * 8))
                    elif 10 <= readBannerBytes <= 13:
                        banner['realHeight'] += (chunk[cursor] << ((readBannerBytes - 10) * 8))
                    elif 14 <= readBannerBytes <= 17:
                        banner['virtualWidth'] += (chunk[cursor] << ((readBannerBytes - 14) * 8))
                    elif 18 <= readBannerBytes <= 21:
                        banner['virtualHeight'] += (chunk[cursor] << ((readBannerBytes - 18) * 8))
                    elif readBannerBytes == 22:
                        banner['orientation'] += chunk[cursor] * 90
                    elif readBannerBytes == 23:
                        banner['quirks'] = chunk[cursor]

                    cursor += 1
                    readBannerBytes += 1
                    if readBannerBytes == bannerLength:
                        self.banner = banner
                        self.logger.debug("minicap initialized: %s" % banner)

                elif readFrameBytes < 4:
                    frameBodyLength += (chunk[cursor] << (readFrameBytes * 8))
                    cursor += 1
                    readFrameBytes += 1
                else:
                    if chunk_len - cursor >= frameBodyLength:
                        frameBody += chunk[cursor: cursor + frameBodyLength]
                        self.handle_image(frameBody)
                        cursor += frameBodyLength
                        frameBodyLength = readFrameBytes = 0
                        frameBody = bytearray()
                    else:
                        frameBody += chunk[cursor:]
                        frameBodyLength -= chunk_len - cursor
                        readFrameBytes += chunk_len - cursor
                        cursor = chunk_len

    def handle_image(self, frameBody):
        # Sanity check for JPG header, only here for debugging purposes.
        if frameBody[0] != 0xFF or frameBody[1] != 0xD8:
            self.logger.warning("Frame body does not start with JPG header")
        self.last_screen = frameBody
        self.last_screen_time = datetime.now()
        # print "Got an image at %s" % self.last_screen_time

    def check_connectivity(self):
        """
        check if droidbot app is connected
        :return: True for connected
        """
        if not self.connected:
            return False
        if self.last_screen_time is None:
            return False
        return True

    def disconnect(self):
        """
        disconnect telnet
        """
        self.connected = False
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception as e:
                print e.message
        if self.minicap_process is not None:
            try:
                self.minicap_process.terminate()
            except Exception as e:
                print e.message
        try:
            forward_remove_cmd = "adb -s %s forward --remove tcp:%d" % (self.device.serial, self.port)
            subprocess.check_call(forward_remove_cmd.split())
        except Exception as e:
            print e.message

if __name__ == "__main__":
    minicap = Minicap()
    try:
        minicap.connect()
    except:
        minicap.disconnect()
        minicap.device.disconnect()
