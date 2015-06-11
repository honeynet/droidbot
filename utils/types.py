# utils for setting up Android environment and sending events
__author__ = 'yuanchun'
import connection

class Device(object):
    """
    this class describes a connected device
    """
    def __init__(self, device_serial):
        """
        create a device
        :param device_name: name of target device
        :param device_host: host of target device, default is localhost
        :param device_port: port num of target device, default is 5554
        :return:
        """
        self.device_serial = device_serial
        # type 0 for real device, 1 for emulator
        self.type = 0
        self.host = ""
        self.port = ""
        self.telnet = None
        self.adb = None
        if self.device_serial.startswith("emulator-"):
            self.type = 1
            self.host = "localhost"
            self.port = int(device_serial[9:])
        # print self.type, self.host, self.port

    def check_connectivity(self):
        """
        check if the device is available
        :return: Ture for available, False for not
        """
        try:
            # try connecting to device
            # TODO find out how to check connectivity
            print "try connecting to device"
        except:
            return False
        return True

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if self.telnet == None:
            from telnetlib import Telnet
            self.telnet = Telnet(self.host, self.port)
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if self.adb == None:
            self.adb = connection.ADB(self.device_serial)
        return self.adb

class App(object):
    """
    this class describes an app
    """
    def __init__(self, package_name, file_path = ""):
        """
        create a App instance
        :param package_name: package name of app
        :param file_path: local file path of app
        :return:
        """
        self.package_name = package_name
        self.file_path = file_path
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


def add_contact(phonenum, first_name="", last_name="", email=""):
    """
    add a contact to device
    :param phonenum:
    :param first_name:
    :param last_name:
    :param email:
    :return:
    """
    # TODO implement this function
    return

def add_sms_log(phonenum, content, send=0):
    """
    add a SMS log to device
    :param phonenum: phonenum of this SMS
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


class UIevent(object):
    """
    this class describes a UI event
    """
    # TODO define this class
    pass


def send_UI_event(uievent):
    """
    send a UI event to device via monkeyrunner
    :param uievent: instance of UIevent
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