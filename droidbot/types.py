# utils for setting up Android environment and sending events
__author__ = 'yuanchun'
import connection
import logging
import time
from com.dtmilano.android.viewclient import ViewClient

DEFAULT_NUM = '1234567890'
DEFAULT_CONTENT = 'Hello world!'


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
        self.display_info = None

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

        self.is_connected = False
        self.connect()
        self.settings = {}
        self.get_settings()
        self.get_display_info()
        assert self.display_info is not None
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
            self.is_connected = True

        except connection.TelnetException:
            self.logger.warning("Cannot connect to telnet.")

    def disconnect(self):
        """
        disconnect current device
        :return:
        """
        self.is_connected = False
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
            # use adbclient class in com.dtmilano.adb.adbclient
            self.adb, self.serial = ViewClient.connectToDeviceOrExit(verbose=True,serialno=self.serial)
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
            kwargs = {'startviewserver': True,
                      'forceviewserveruse': True,
                      'autodump': False,
                      'ignoreuiautomatorkilled': True}
            self.view_client = ViewClient(self.adb, self.serial, **kwargs)
        return self.view_client

    def is_foreground(self, app):
        """
        check if app is in foreground of device
        :param app: App
        :return: boolean
        """
        package = app.get_package_name()
        focused_window_name = self.get_adb().getTopActivityName()
        return focused_window_name.startswith(package)

    def get_display_info(self):
        """
        get device display infomation, including width, height, and density
        :return: dict, display_info
        """
        if self.display_info is None:
            self.display_info = self.get_adb().getDisplayInfo()
        return self.display_info

    def device_prepare(self):
        """
        unlock screen
        skip first-use tutorials
        etc
        :return:
        """
        assert self.get_adb() is not None
        assert self.get_view_client() is not None

        # unlock screen
        self.get_adb().unlock()

        # TODO set screen to never locked
        # TODO skip first-use turorials

    def add_env(self, env):
        """
        set env to the device
        :param env: instance of AppEnv
        """
        self.logger.info("deploying env: %s" % env)
        env.deploy(self)

    def add_contact(self, contact_data):
        """
        add a contact to device
        :param contact_data: dict of contact, should have keys like name, phone, email
        :return:
        """
        assert self.get_adb() is not None
        contact_intent = Intent(prefix="start",
                                action="android.intent.action.INSERT",
                                mime_type="vnd.android.cursor.dir/contact",
                                extra_string=contact_data)
        self.send_intent(intent=contact_intent)
        time.sleep(2)
        self.get_adb().press("BACK")
        time.sleep(2)
        self.get_adb().press("BACK")

    def receive_call(self, phone=DEFAULT_NUM):
        """
        simulate a income phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.get_telnet() is not None
        return self.get_telnet().run_cmd("gsm call %s" % phone)

    def cancel_call(self, phone=DEFAULT_NUM):
        """
        cancel phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.get_telnet() is not None
        return self.get_telnet().run_cmd("gsm cancel %s" % phone)

    def accept_call(self, phone=DEFAULT_NUM):
        """
        accept phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.get_telnet() is not None
        return self.get_telnet().run_cmd("gsm accept %s" % phone)

    def call(self, phone=DEFAULT_NUM):
        """
        simulate a outcome phonecall
        :param phone: str, phonenum
        :return:
        """
        call_intent = Intent(prefix='start',
                             action="android.intent.action.CALL",
                             data_uri="tel:%s" % phone)
        self.send_intent(intent=call_intent)

    def send_sms(self, phone=DEFAULT_NUM, content=DEFAULT_CONTENT):
        """
        send a SMS
        :param phone: str, phone number of receiver
        :param content: str, content of sms
        :return:
        """
        send_sms_intent = Intent(prefix='start',
                                 action="android.intent.action.SENDTO",
                                 data_uri="sms:%s" % phone,
                                 extra_string={'sms_body':content},
                                 extra_boolean={'exit_on_sent':'true'})
        self.send_intent(intent=send_sms_intent)
        time.sleep(2)
        self.get_adb().press('66')

    def receive_sms(self, phone, content=""):
        """
        receive a SMS
        :param phone: str, phone number of sender
        :param content: str, content of sms
        :return:
        """
        assert self.get_telnet() is not None
        self.get_telnet().run_cmd("sms send %s '%s'" % (phone, content))

    def set_gps(self, x, y):
        """
        set GPS positioning to x,y
        :param x: float
        :param y: float
        :return:
        """
        assert self.get_telnet() is not None
        self.get_telnet().run_cmd("geo fix %s %s" % (x, y))

    def set_continuous_gps(self, center_x, center_y, delta_x, delta_y):
        import threading
        gps_thread = threading.Thread(
            target=self.set_continuous_gps_blocked,
            args=(center_x, center_y, delta_x, delta_y))
        gps_thread.start()

    def set_continuous_gps_blocked(self, center_x, center_y, delta_x, delta_y):
        """
        simulate GPS on device via telnet
        this method is blocked
        """
        import random, time
        while self.is_connected:
            x = random.random() * delta_x * 2 + center_x - delta_x
            y = random.random() * delta_y * 2 + center_y - delta_y
            self.set_gps(x, y)
            time.sleep(3)

    def get_settings(self):
        """
        get device settings via adb
        """
        db_name = "/data/data/com.android.providers.settings/databases/settings.db"

        system_settings = {}
        out = self.get_adb().shell("sqlite3 %s \"select * from %s\"" % (db_name, "system"))
        out_lines = out.splitlines()
        for line in out.splitlines():
            segs = line.split('|')
            if len(segs) != 3:
                continue
            system_settings[segs[1]] = segs[2]

        secure_settings = {}
        out = self.get_adb().shell("sqlite3 %s \"select * from %s\"" % (db_name, "secure"))
        out_lines = out.splitlines()
        for line in out_lines:
            segs = line.split('|')
            if len(segs) != 3:
                continue
            secure_settings[segs[1]] = segs[2]

        self.settings['system'] = system_settings
        self.settings['secure'] = secure_settings
        return self.settings

    def change_settings(self, table_name, name, value):
        """
        dangerous method, by calling this, change settings.db in device
        be very careful for sql injection
        :param table_name: table name to work on, usually it is system or secure
        :param name: settings name to set
        :param value: settings value to set
        """
        db_name = "/data/data/com.android.providers.settings/databases/settings.db"

        self.get_adb().shell("sqlite3 %s \"update '%s' set value='%s' where name='%s'\""
                             % (db_name, table_name, value, name))
        self.get_settings()

    def send_intent(self, intent):
        """
        send an intent to device via am (ActivityManager)
        :param intent: instance of Intent
        :return:
        """
        assert self.get_adb() is not None
        assert intent is not None
        cmd = intent.get_cmd()
        self.get_adb().shell(cmd)

    def send_event(self, event):
        """
        send one event to device
        :param event: the event to be sent
        :return:
        """
        self.logger.info("sending event: %s" % event)
        event.send(self)

    def start_app(self, app):
        """
        start an app on the device
        :param app: instance of App, or str of package name
        :return:
        """
        package_name = ""
        if isinstance(app, str):
            package_name = app
        if isinstance(app, App):
            package_name = app.get_package_name()
        else:
            self.logger.warning("unsupported param " + app + " with type: ", type(app))
            return
        self.get_adb().startActivity(uri=package_name)


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
            self.logger.warning("no app given, will operate on whole device")
        elif app_path:
            self.get_androguard_analysis()

    def get_androguard_analysis(self):
        """
        run static analysis of app
        :return:
        """
        if self.androguard is None:
            self.androguard = AndroguardAnalysis(self.app_path)
        return self.androguard

    def get_package_name(self):
        """
        get package name of current app
        :return:
        """
        if self.package_name is not None:
            return self.package_name
        elif self.get_androguard_analysis() is not None:
            self.package_name = self.get_androguard_analysis().a.get_package()
            return self.package_name
        else:
            self.logger.warning("can not get package name")
            return None

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
        :param app_path: local file path of app, should not be None
        analyse app specified by app_path
        """
        from androguard.androlyze import AnalyzeAPK
        self.a, self.d, self.dx = AnalyzeAPK(app_path)


class Intent(object):
    """
    this class describes a intent event
    """
    def __init__(self, prefix="start", action=None, data_uri=None, mime_type=None, category=None,
                 component=None, flag=None, extra_keys=[], extra_string={}, extra_boolean={},
                 extra_int={}, extra_long={}, extra_float={}, extra_uri={}, extra_component={},
                 extra_array_int={}, extra_array_long={}, extra_array_float={}, flags=[], suffix=""):
        self.event_type = 'intent'
        self.prefix = prefix
        self.action = action
        self.data_uri = data_uri
        self.mime_type = mime_type
        self.category = category
        self.component = component
        self.flag = flag
        self.extra_keys = extra_keys
        self.extra_string = extra_string
        self.extra_boolean = extra_boolean
        self.extra_int = extra_int
        self.extra_long = extra_long
        self.extra_float = extra_float
        self.extra_uri = extra_uri
        self.extra_component = extra_component
        self.extra_array_int = extra_array_int
        self.extra_array_long = extra_array_long
        self.extra_array_float = extra_array_float
        self.flags = flags
        self.suffix = suffix
        self.cmd = None
        self.get_cmd()

    def get_cmd(self):
        """
        convert this intent to cmd string
        :rtype : object
        :return: str, cmd string
        """
        if self.cmd is not None:
            return self.cmd
        cmd = "am "
        if self.prefix:
            cmd += self.prefix
        if self.action is not None:
            cmd += " -a " + self.action
        if self.data_uri is not None:
            cmd += " -d " + self.data_uri
        if self.mime_type is not None:
            cmd += " -t " + self.mime_type
        if self.category is not None:
            cmd += " -c " + self.category
        if self.component is not None:
            cmd += " -n " + self.component
        if self.flag is not None:
            cmd += " -f " + self.flag
        if self.extra_keys:
            for key in self.extra_keys:
                cmd += " --esn '%s'" % key
        if self.extra_string:
            for key in self.extra_string.keys():
                cmd += " -e '%s' '%s'" % (key, self.extra_string[key])
        if self.extra_boolean:
            for key in self.extra_boolean.keys():
                cmd += " -ez '%s' %s" % (key, self.extra_boolean[key])
        if self.extra_int:
            for key in self.extra_int.keys():
                cmd += " -ei '%s' %s" % (key, self.extra_int[key])
        if self.extra_long:
            for key in self.extra_long.keys():
                cmd += " -el '%s' %s" % (key, self.extra_long[key])
        if self.extra_float:
            for key in self.extra_float.keys():
                cmd += " -ef '%s' %s" % (key, self.extra_float[key])
        if self.extra_uri:
            for key in self.extra_uri.keys():
                cmd += " -eu '%s' '%s'" % (key, self.extra_uri[key])
        if self.extra_component:
            for key in self.extra_component.keys():
                cmd += " -ecn '%s' %s" % (key, self.extra_component[key])
        if self.extra_array_int:
            for key in self.extra_array_int.keys():
                cmd += " -eia '%s' %s" % (key, ",".join(self.extra_array_int[key]))
        if self.extra_array_long:
            for key in self.extra_array_long.keys():
                cmd += " -ela '%s' %s" % (key, ",".join(self.extra_array_long[key]))
        if self.extra_array_float:
            for key in self.extra_array_float.keys():
                cmd += " -efa '%s' %s" % (key, ",".join(self.extra_array_float[key]))
        if self.flags:
            cmd += " " + " ".join(self.flags)
        if self.suffix:
            cmd += " " + self.suffix
        self.cmd = cmd
        return self.cmd