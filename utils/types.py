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

        try:
            self.get_adb()
            self.get_telnet()
        except connection.TelnetException:
            self.logger.warning("Cannot connect to telnet.")
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
            return result
        except:
            return False

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if self.telnet == None:
            self.telnet = connection.TelnetConsole(self)
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if self.adb == None:
            self.adb = connection.ADB(self)
        return self.adb


class App(object):
    """
    this class describes an app
    """
    def __init__(self, app_path = ""):
        """
        create a App instance
        :param app_path: local file path of app
        :return:
        """
        self.app_path = app_path
        self.static_result = {}

    def get_static_result(self):
        """
        get static analysis result of app
        :return: a dict of static analysis result
        """
        if self.static_result:
            return self.static_result
        # TODO do static analysis and get the result
        return self.static_result


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