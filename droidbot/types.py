# utils for setting up Android environment and sending events
__author__ = 'yuanchun'
import connection
import logging
from com.dtmilano.android.viewclient import ViewClient


class Device(object):
    """
    this class describes a connected device
    """
    def __init__(self, device_serial, is_emulator=True):
        """
        create a device
        :param device_serial: serial number of target device
        :param is_emulator: boolean, type of device, True for emulator, False for real device
        :return:
        """
        self.logger = logging.getLogger('Device')
        self.serial = device_serial
        # type 0 for real device, 1 for emulator
        self.is_emulator = is_emulator
        self.adb = None
        self.telnet = None
        self.monkeyrunner = None
        self.view_client = None

        if self.is_emulator:
            self.adb_enabled = True
            self.telnet_enabled = True
            self.monkeyrunner_enabled = False
            self.view_client_enabled = True
        else:
            self.adb_enabled = True
            self.telnet_enabled = True
            self.monkeyrunner_enabled = False
            self.view_client_enabled = False

        self.connect()
        # self.check_connectivity()
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

            if self.adb_enabled and self.adb and self.adb.check_connectivity():
                self.logger.info("ADB is connected")
            else:
                self.logger.warning("ADB is not connected")
                result = False

            if self.telnet_enabled and self.telnet and self.telnet.check_connectivity():
                self.logger.info("Telnet is connected")
            else:
                self.logger.warning("Telnet is not connected")
                result = False

            if self.monkeyrunner_enabled and self.monkeyrunner and self.monkeyrunner.check_connectivity():
                self.logger.info("monkeyrunner is connected")
            else:
                self.logger.warning("monkeyrunner is not connected")
                result = False

            if self.view_client_enabled and self.view_client:
                self.logger.info("view_client is connected")
            else:
                self.logger.warning("view_client is not connected")
                result = False
            return result
        except:
            return False

    def connect(self):
        """
        connect this device via adb, telnet and monkeyrunner
        :return:
        """
        try:
            if self.adb_enabled:
                self.get_adb()
            if self.telnet_enabled:
                self.get_telnet()
            if self.monkeyrunner_enabled:
                self.get_monkeyrunner()
            if self.view_client_enabled:
                self.get_view_client()

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
        if self.view_client:
            self.view_client.__del__()

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if self.telnet_enabled and not self.telnet:
            self.telnet = connection.TelnetConsole(self)
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if self.adb_enabled and not self.adb:
            self.adb = connection.ADB(self)
        return self.adb

    def get_monkeyrunner(self):
        """
        get monkeyrunner connection of the device
        :return:
        """
        if self.monkeyrunner_enabled and not self.monkeyrunner:
            self.monkeyrunner = connection.MonkeyRunner(self)
        return self.monkeyrunner

    def get_view_client(self):
        """
        get view_client connection of the device
        :return:
        """
        if self.view_client_enabled and not self.view_client:
            kwargs1 = {'verbose': True, 'ignoresecuredevice': True, 'serialno': self.serial}
            kwargs2 = {'startviewserver': True, 'forceviewserveruse': True, 'autodump': False, 'ignoreuiautomatorkilled': True}
            self.view_client = ViewClient(*ViewClient.connectToDeviceOrExit(**kwargs1), **kwargs2)
        return self.view_client

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
        self.androguard = None

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
        self.androguard = AndroguardAnalysis(self.app_path)

    def get_coverage(self):
        """
        calculate method coverage
        idea:
        in dalvik, the dvmFastMethodTraceEnter in profle.cpp will be called in each method
        dvmFastMethodTraceEnter takes Method* as an argument
        struct Method is defined in vm/oo/Object.cpp
        Method has a field clazz (struct ClassObject)
        ClassObject has a field pDvmDex (struct DvmDex in DvmDex.h)
        DvmDex represent a dex file.
        Hopefully, by monitoring method and comparing the belong dex file,
        we are able to record each invoked method call of app.
        coverage = (methods invoked) / (method declared)
        """
        pass

class AndroguardAnalysis(object):
    """
    analysis result of androguard
    """
    def __init__(self, app_path):
        """
        :param app_path: local file path of app
        analyse app specified by app_path
        """
        from androguard.androlyze import AnalyzeAPK
        self.a, self.d, self.dx = AnalyzeAPK(app_path)


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