import logging
import socket
import subprocess

MINICAP_REMOTE_ADDR = "localabstract:minicap"


class MinicapException(Exception):
    """
    Exception in minicap connection
    """
    pass


class Minicap(object):
    """
    a connection with droidbot app.
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

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connected = True
        self.banner = None

        try:
            # forward host port to remote port
            serial_cmd = "" if device is None else "-s " + device.serial
            forward_cmd = "adb %s forward tcp:%d %s" % (serial_cmd, self.port, MINICAP_REMOTE_ADDR)
            subprocess.check_call(forward_cmd.split())
            self.sock.connect((self.host, self.port))
            import threading
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.start()
        except socket.error, ex:
            self.connected = False
            raise MinicapException()

    def start(self):
        device = self.device
        if device is not None:
            # install minicap
            import pkg_resources
            local_minicap_path = pkg_resources.resource_filename("droidbot", "resources/minicap")
            remote_minicap_path = "/data/local/tmp/minicap-devel"
            device.get_adb().shell("mkdir %s" % remote_minicap_path)
            abi = device.get_adb().get_property('ro.product.cpu.abi')
            sdk = device.get_sdk_version()
            if sdk >= 16:
                minicap_bin = "minicap"
            else:
                minicap_bin = "minicap-nopie"
            device.push_file(local_file="%s/libs/%s/%s" % (local_minicap_path, abi, minicap_bin),
                             remote_dir=remote_minicap_path)
            device.push_file(local_file="%s/jni/libs/android-%s/%s/minicap.so" % (local_minicap_path, sdk, abi),
                             remote_dir=remote_minicap_path)
            display = device.get_display_info(refresh=True)

            device.get_adb().shell("LD_LIBRARY_PATH=%s %s/minicap -h" % (remote_minicap_path, remote_minicap_path))

    def listen_messages(self):
        self.logger.debug("start listening messages")
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

        while self.connected:
            chunk = bytearray(self.sock.recv(CHUNK_SIZE))
            # print chunk
            if not chunk:
                continue
            chunk_len = len(chunk)
            cursor = 0
            while cursor < chunk_len:
                if (readBannerBytes < bannerLength):
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
                        self.logger.info("minicap initialized: %s" % banner)

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
        print "received a jpg."

    def check_connectivity(self):
        """
        check if droidbot app is connected
        :return: True for connected
        """
        return self.connected

    def disconnect(self):
        """
        disconnect telnet
        """
        self.sock.close()
        self.connected = False
        self.logger.debug("disconnected")

if __name__ == "__main__":
    minicap = Minicap()
