import logging
import socket
import subprocess
import time
import json
from adapter import Adapter

DROIDBOT_APP_REMOTE_ADDR = "tcp:7336"
DROIDBOT_APP_PACKAGE = "io.github.ylimit.droidbotapp"
ACCESSIBILITY_SERVICE = DROIDBOT_APP_PACKAGE + "/com.github.privacystreams.accessibility.PSAccessibilityService"


class DroidBotAppConnException(Exception):
    """
    Exception in telnet connection
    """
    pass


class DroidBotAppConn(Adapter):
    """
    a connection with droidbot app.
    """
    def __init__(self, device=None):
        """
        initiate a emulator console via telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger('DroidBotAppConn')
        self.host = "localhost"
        self.port = 7336
        if device is None:
            from droidbot.device import Device
            device = Device()
        self.device = device
        self.connected = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.last_acc_event = None

    def set_up(self):
        device = self.device
        if DROIDBOT_APP_PACKAGE in device.adb.get_installed_apps():
            self.logger.debug("DroidBot app was already installed.")
        else:
            # install droidbot app
            import pkg_resources
            from droidbot.app import App
            droidbot_app_path = pkg_resources.resource_filename("droidbot", "resources/droidbotApp.apk")
            droidbot_app = App(app_path=droidbot_app_path)
            device.install_app(droidbot_app)
            self.logger.debug("DroidBot app installed.")

        device.adb.disable_accessibility_service(ACCESSIBILITY_SERVICE)
        device.adb.enable_accessibility_service(ACCESSIBILITY_SERVICE)
        if ACCESSIBILITY_SERVICE not in device.adb.get_enabled_accessibility_services():
            # accessibility not enabled, need to enable manually
            self.logger.warning("Please enable accessibility for DroidBot app manually.")
        # device.start_app(droidbot_app)
        while ACCESSIBILITY_SERVICE not in device.get_service_names():
            time.sleep(1)

    def tear_down(self):
        self.device.uninstall_app(DROIDBOT_APP_PACKAGE)

    def connect(self):
        try:
            # forward host port to remote port
            serial_cmd = "" if self.device is None else "-s " + self.device.serial
            forward_cmd = "adb %s forward tcp:%d %s" % (serial_cmd, self.port, DROIDBOT_APP_REMOTE_ADDR)
            subprocess.check_call(forward_cmd.split())
            self.sock.connect((self.host, self.port))
            import threading
            listen_thread = threading.Thread(target=self.listen_messages)
            listen_thread.start()
        except socket.error as ex:
            self.connected = False
            self.logger.warning(ex.message)
            raise DroidBotAppConnException()

    def listen_messages(self):
        self.logger.debug("start listening messages")
        CHUNK_SIZE = 1024
        read_message_bytes = 0
        message_len = 0
        message = ""
        self.connected = True
        while self.connected:
            chunk = self.sock.recv(CHUNK_SIZE)
            # print chunk
            if not chunk:
                continue
            chunk_len = len(chunk)
            cursor = 0
            while cursor < chunk_len:
                b = ord(chunk[cursor])
                if read_message_bytes == 0:
                    if b != 0xff:
                        continue
                elif read_message_bytes == 1:
                    if b != 0x00:
                        continue
                elif read_message_bytes < 6:
                    message_len += b << ((5 - read_message_bytes) * 8)
                    # if read_message_bytes == 5:
                    #     print "received a message with a length of %d" % message_len
                else:
                    if chunk_len - cursor >= message_len:
                        message += chunk[cursor:(cursor + message_len)]
                        # print "received a message:"
                        # print message
                        self.handle_message(message)
                        cursor += message_len
                        message_len = 0
                        read_message_bytes = 0
                        message = ""
                        continue
                    else:
                        message += chunk[cursor:]
                        message_len -= (chunk_len - cursor)
                        read_message_bytes += (chunk_len - cursor)
                        break
                read_message_bytes += 1
                cursor += 1

    def handle_message(self, message):
        # print message
        tag_index = message.find(" >>> ")
        if tag_index != -1:
            tag = message[:tag_index]
            if tag == "AccEvent":
                body = json.loads(message[(tag_index + 5):])
                self.last_acc_event = body
            else:
                self.logger.warning("Unhandled message from droidbot app: " + tag)

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
        try:
            forward_remove_cmd = "adb -s %s forward --remove tcp:%d" % (self.device.serial, self.port)
            subprocess.check_call(forward_remove_cmd.split())
        except Exception as e:
            print e.message

    def __view_tree_to_list(self, view_tree, view_list):
        tree_id = len(view_list)
        view_tree['temp_id'] = tree_id
        view_list.append(view_tree)
        children_ids = []
        for child_tree in view_tree['children']:
            child_tree['parent'] = tree_id
            self.__view_tree_to_list(child_tree, view_list)
            children_ids.append(child_tree['temp_id'])
        view_tree['children'] = children_ids

    def get_views(self):
        import copy
        if not self.last_acc_event:
            return None
        view_tree = copy.deepcopy(self.last_acc_event['root_node'])
        if not view_tree:
            return None
        view_tree['parent'] = -1
        view_list = []
        self.__view_tree_to_list(view_tree, view_list)
        return view_list

if __name__ == "__main__":
    droidbot_app_conn = DroidBotAppConn()
    droidbot_app_conn.setup()
    droidbot_app_conn.connect()
