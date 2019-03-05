import logging
import socket
import subprocess
import time
from datetime import datetime
from .adapter import Adapter


MINICAP_REMOTE_ADDR = "localabstract:minicap"
ROTATION_CHECK_INTERVAL_S = 1 # Check rotation once per second


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
        initiate a minicap connection
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

        self.remote_minicap_path = "/data/local/tmp/minicap-devel"

        self.sock = None
        self.connected = False
        self.minicap_process = None
        self.banner = None
        self.width = -1
        self.height = -1
        self.orientation = -1

        self.last_screen = None
        self.last_screen_time = None
        self.last_views = []
        self.last_rotation_check_time = datetime.now()

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
            delete_minicap_cmd = "adb -s %s shell rm -r %s" % (self.device.serial, self.remote_minicap_path)
            p = subprocess.Popen(delete_minicap_cmd.split(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            out, err = p.communicate()
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
        self.width = w
        self.height = h
        self.orientation = o

        size_opt = "%dx%d@%dx%d/%d" % (w, h, w, h, o)
        grant_minicap_perm_cmd = "adb -s %s shell chmod -R a+x %s" % \
                                 (device.serial, self.remote_minicap_path)
        start_minicap_cmd = "adb -s %s shell LD_LIBRARY_PATH=%s %s/minicap -P %s" % \
                            (device.serial, self.remote_minicap_path, self.remote_minicap_path, size_opt)
        self.logger.debug("starting minicap: " + start_minicap_cmd)

        p = subprocess.Popen(grant_minicap_perm_cmd.split(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        out, err = p.communicate()

        self.minicap_process = subprocess.Popen(start_minicap_cmd.split(),
                                                stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        # Wait 2 seconds for starting minicap
        time.sleep(2)
        self.logger.debug("minicap started.")

        try:
            # forward host port to remote port
            forward_cmd = "adb -s %s forward tcp:%d %s" % (device.serial, self.port, MINICAP_REMOTE_ADDR)
            subprocess.check_call(forward_cmd.split())
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            import threading
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.start()
        except socket.error as e:
            self.connected = False
            self.logger.warning(e)
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
            while cursor < chunk_len and self.connected:
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
        print("[CONNECTION] %s is disconnected" % self.__class__.__name__)

    def handle_image(self, frameBody):
        # Sanity check for JPG header, only here for debugging purposes.
        if frameBody[0] != 0xFF or frameBody[1] != 0xD8:
            self.logger.warning("Frame body does not start with JPG header")
        self.last_screen = frameBody
        self.last_screen_time = datetime.now()
        self.last_views = None
        self.logger.debug("Received an image at %s" % self.last_screen_time)
        self.check_rotation()

    def check_rotation(self):
        current_time = datetime.now()
        if (current_time - self.last_rotation_check_time).total_seconds() < ROTATION_CHECK_INTERVAL_S:
            return

        display = self.device.get_display_info(refresh=True)
        if 'orientation' in display:
            cur_orientation = display['orientation'] * 90
            if cur_orientation != self.orientation:
                self.device.handle_rotation()
        self.last_rotation_check_time = current_time

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
                print(e)
        if self.minicap_process is not None:
            try:
                self.minicap_process.terminate()
            except Exception as e:
                print(e)
        try:
            forward_remove_cmd = "adb -s %s forward --remove tcp:%d" % (self.device.serial, self.port)
            p = subprocess.Popen(forward_remove_cmd.split(), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            out, err = p.communicate()
        except Exception as e:
            print(e)

    def get_views(self):
        """
        get UI views using cv module
        opencv-python need to be installed for this function
        :return: a list of views
        """
        if not self.last_screen:
            self.logger.warning("last_screen is None")
            return None
        if self.last_views:
            return self.last_views

        from . import cv
        img = cv.load_image_from_buf(self.last_screen)
        view_bounds = cv.find_views(img)
        root_view = {
            "class": "CVViewRoot",
            "bounds": [[0, 0], [self.width, self.height]],
            "enabled": True,
            "temp_id": 0
        }
        views = [root_view]
        temp_id = 1
        for x,y,w,h in view_bounds:
            view = {
                "class": "CVView",
                "bounds": [[x,y], [x+w, y+h]],
                "enabled": True,
                "temp_id": temp_id,
                "signature": cv.calculate_dhash(img[y:y+h, x:x+w]),
                "parent": 0,
                "children": []
            }
            views.append(view)
            temp_id += 1
        root_view["children"] = list(range(1, temp_id))

        self.last_views = views
        return views


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    minicap = Minicap()
    try:
        minicap.set_up()
        minicap.connect()
    except:
        minicap.disconnect()
        minicap.tear_down()
        minicap.device.disconnect()
