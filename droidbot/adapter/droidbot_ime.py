# coding=utf-8

import logging
import time

from .adapter import Adapter

DROIDBOT_APP_PACKAGE = "io.github.ylimit.droidbotapp"
IME_SERVICE = DROIDBOT_APP_PACKAGE + "/.DroidBotIME"


class DroidBotImeException(Exception):
    """
    Exception in telnet connection
    """
    pass


class DroidBotIme(Adapter):
    """
    a connection with droidbot ime app.
    """
    def __init__(self, device=None):
        """
        initiate a emulator console via telnet
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if device is None:
            from droidbot.device import Device
            device = Device()
        self.device = device
        self.connected = False

    def set_up(self):
        device = self.device
        if DROIDBOT_APP_PACKAGE in device.adb.get_installed_apps():
            self.logger.debug("DroidBot app was already installed.")
        else:
            # install droidbot app
            try:
                import pkg_resources
                droidbot_app_path = pkg_resources.resource_filename("droidbot", "resources/droidbotApp.apk")
                install_cmd = ["install", droidbot_app_path]
                self.device.adb.run_cmd(install_cmd)
                self.logger.debug("DroidBot app installed.")
            except Exception as e:
                self.logger.warning(e)
                self.logger.warning("Failed to install DroidBotApp.")

    def tear_down(self):
        self.device.uninstall_app(DROIDBOT_APP_PACKAGE)

    def connect(self):
        r_enable = self.device.adb.shell("ime enable %s" % IME_SERVICE)
        if "now enabled" in r_enable or "already enabled" in r_enable:
            r_set = self.device.adb.shell("ime set %s" % IME_SERVICE)
            if f"{IME_SERVICE} selected" in r_set:
                self.connected = True
                return
        self.logger.warning("Failed to connect DroidBotIME!")

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
        self.connected = False
        r_disable = self.device.adb.shell("ime disable %s" % IME_SERVICE)
        if r_disable.endswith("now disabled"):
            self.connected = False
            print("[CONNECTION] %s is disconnected" % self.__class__.__name__)
            return
        self.logger.warning("Failed to disconnect DroidBotIME!")

    def input_text(self, text, mode=0):
        """
        Input text to target device
        :param text: text to input, can be unicode format
        :param mode: 0 - set text; 1 - append text.
        """
        input_cmd = "am broadcast -a DROIDBOT_INPUT_TEXT --es text \"%s\" --ei mode %d" % (text, mode)
        self.device.adb.shell(str(input_cmd))


if __name__ == "__main__":
    droidbot_ime_conn = DroidBotIme()
    droidbot_ime_conn.set_up()
    droidbot_ime_conn.connect()
    droidbot_ime_conn.input_text("hello world!", 0)
    droidbot_ime_conn.input_text("世界你好!", 1)
    time.sleep(2)
    droidbot_ime_conn.input_text("再见。Bye bye.", 0)
    droidbot_ime_conn.disconnect()
    droidbot_ime_conn.tear_down()
