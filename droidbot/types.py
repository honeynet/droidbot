# utils for setting up Android environment and sending events
__author__ = 'yuanchun'
import connection
import logging


class Device(object):
    """
    this class describes a connected device
    """
    def __init__(self, device_serial):
        """
        create a device
        :param device_serial: serial number of target device
        :return:
        """
        self.logger = logging.getLogger('Device')
        self.serial = device_serial
        # type 0 for real device, 1 for emulator
        self.type = 0
        self.adb = None
        self.telnet = None
        self.monkeyrunner = None

        self.connect()
        self.check_connectivity()
        # print self.type, self.host, self.port

    def check_connectivity(self):
        """
        check if the device is available
        :return: Ture for available, False for not
        """
        try:
            # try connecting to device
            self.logger.info("checking connectivity...")
            result = True
            if self.adb and self.adb.check_connectivity():
                self.logger.info("ADB is connected")
            else:
                self.logger.warning("ADB is not connected")
                result = False
            if self.telnet and self.telnet.check_connectivity():
                self.logger.info("Telnet is connected")
            else:
                self.logger.warning("Telnet is not connected")
                result = False
            # if self.monkeyrunner and self.monkeyrunner.check_connectivity():
            #     self.logger.info("monkeyrunner is connected")
            # else:
            #     self.logger.warning("monkeyrunner is not connected")
            #     result = False
            return result
        except:
            return False

    def connect(self):
        """
        connect this device via adb, telnet and monkeyrunner
        :return:
        """
        try:
            self.get_adb()
            self.get_telnet()
            # self.get_monkeyrunner()
        except connection.TelnetException:
            self.logger.warning("Cannot connect to telnet.")

    def disconnect(self):
        """
        disconnect current device
        :return:
        """
        if self.adb:
            self.adb.disconnect()
        if self.telnet:
            self.telnet.disconnect()
        if self.monkeyrunner:
            self.monkeyrunner.disconnect()

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if not self.telnet:
            self.telnet = connection.TelnetConsole(self)
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if not self.adb:
            self.adb = connection.ADB(self)
        return self.adb

    def get_monkeyrunner(self):
        """
        get monkeyrunner connection of the device
        :return:
        """
        if not self.monkeyrunner:
            self.monkeyrunner = connection.MonkeyRunner(self)
        return self.monkeyrunner

    def set_env(self, env):
        """
        set env to the device
        :param env: instance of AppEnv
        """
        # TODO implement this method

    def send_event(self, event, state=None):
        """
        send one event to device
        :param event: the event to be sent
        :return:
        """
        # TODO implement this method

class App(object):
    """
    this class describes an app
    """
    def __init__(self, package_name=None, app_path=None):
        """
        create a App instance
        :param app_path: local file path of app
        :return:
        """
        self.logger = logging.getLogger('App')
        self.package_name = package_name
        self.app_path = app_path

        if not package_name and not app_path:
            self.logger.warning("no app given")
        elif app_path:
            self.run_static_analysis()
            self.package_name = self.static_result['package_name']
        self.static_result = {}

    def run_static_analysis(self):
        """
        run static analysis of app
        :return:
        """
        # TODO do static analysis
        self.static_result = {}


def add_contact(phone_num, first_name="", last_name="", email=""):
    """
    add a contact to device
    :param phone_num:
    :param first_name:
    :param last_name:
    :param email:
    :return:
    """
    # TODO implement this function
    return

def add_sms_log(phone_num, content, send=0):
    """
    add a SMS log to device
    :param phone_num: phone_num of this SMS
    :param content: SMS content
    :param send: 0 for send, 1 for receive
    :return:
    """
    # TODO implement this function
    return

def set_system_setting(setting_name, setting_value):
    """
    set a system setting to a certain value
    :param setting_name: name of setting, could be volume, brightness
    :param setting_value: value of setting
    :return:
    """
    # TODO figure how to, and implement
    return

def set_gps(start_axis, range = 10):
    """
    simulate GPS on device via telnet
    :param start_axis: start position given by (latitude, longitude)
    :param range: GPS range
    :return:
    """
    # TODO implement this method
    return


class UIEvent(object):
    """
    this class describes a UI event
    """
    # TODO define this class
    pass


def send_UI_event(ui_event):
    """
    send a UI event to device via monkeyrunner
    :param ui_event: instance of UIEvent
    :return:
    """
    # TODO implement this function


class IntentEvent(object):
    """
    this class describes a intent event
    """
    # TODO define this class
    pass


def set_intent_event(intent_event):
    """
    send an intent to device via am (ActivityManager)
    :param intent_event: instance of IntentEvent
    :return:
    """
    # TODO implement this function
    pass