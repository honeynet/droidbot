# utils for setting up Android environment and sending events
import subprocess

__author__ = 'yuanchun'
import connection
import logging
import time
import os
import re
from com.dtmilano.android.viewclient import ViewClient

DEFAULT_NUM = '1234567890'
DEFAULT_CONTENT = 'Hello world!'


class Device(object):
    """
    this class describes a connected device
    """
    def __init__(self, device_serial=None, is_emulator=True, output_dir=None):
        """
        create a device
        :param device_serial: serial number of target device
        :param is_emulator: boolean, type of device, True for emulator, False for real device
        :return:
        """
        self.logger = logging.getLogger('Device')

        self.serial = device_serial
        # is_emulator 0 for real device, 1 for emulator
        self.is_emulator = is_emulator
        self.adb = None
        self.telnet = None
        self.monkeyrunner = None
        self.view_client = None
        self.settings = {}
        self.display_info = None

        self.output_dir = output_dir
        if self.output_dir is None:
            self.output_dir = os.path.abspath("droidbot_out")
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)

        if self.is_emulator:
            self.adb_enabled = True
            self.telnet_enabled = True
            self.monkeyrunner_enabled = False
            self.view_client_enabled = True
        else:
            self.adb_enabled = True
            self.telnet_enabled = False
            self.monkeyrunner_enabled = False
            self.view_client_enabled = True

        self.is_connected = False
        self.connect()
        self.get_display_info()
        self.logcat = self.redirect_logcat()
        # assert self.display_info is not None
        # self.check_connectivity()
        # print self.is_emulator, self.host, self.port

    def redirect_logcat(self, output_dir=None):
        if output_dir is None:
            output_dir = self.output_dir
        logcat_file = open("%s/logcat.log" % output_dir, "w")
        import subprocess
        subprocess.check_call(["adb", "logcat", "-c"])
        logcat = subprocess.Popen(["adb", "logcat"],
                                  stdin=subprocess.PIPE,
                                  stdout=logcat_file)
        return logcat

    def check_connectivity(self):
        """
        check if the device is available
        :return: Ture for available, False for not
        """
        try:
            # try connecting to device
            self.logger.info("checking connectivity...")
            result = True

            if self.adb_enabled and self.adb and self.adb.checkConnected():
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

    def wait_for_device(self):
        """
        wait until the device is fully booted
        :return:
        """
        self.logger.info("waiting for device")
        try:
            subprocess.check_call(["adb", "wait-for-device"])
            while True:
                out = subprocess.check_output(["adb", "shell", "getprop", "init.svc.bootanim"]).split()[0]
                if out == "stopped":
                    break
                time.sleep(3)
        except:
            self.logger.warning("error waiting for device")


    def connect(self):
        """
        connect this device via adb, telnet and monkeyrunner
        :return:
        """
        try:
            # wait for emulator to start
            self.wait_for_device()
            if self.adb_enabled:
                self.get_adb()

            if self.telnet_enabled:
                self.get_telnet()

            if self.monkeyrunner_enabled:
                self.get_monkeyrunner()

            if self.view_client_enabled:
                self.get_view_client()

            time.sleep(3)
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
            self.adb.close()
        if self.telnet:
            self.telnet.disconnect()
        if self.monkeyrunner:
            self.monkeyrunner.disconnect()
        if self.view_client:
            self.view_client = None
        self.logcat.terminate()

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if self.telnet_enabled and self.telnet is None:
            self.telnet = connection.TelnetConsole(self)
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if self.adb_enabled and self.adb is None:
            # use adbclient class in com.dtmilano.adb.adbclient
            self.adb, self.serial = ViewClient.connectToDeviceOrExit(verbose=True,serialno=self.serial)
        return self.adb

    def get_monkeyrunner(self):
        """
        get monkeyrunner connection of the device
        :return:
        """
        if self.monkeyrunner_enabled and self.monkeyrunner is None:
            self.monkeyrunner = connection.MonkeyRunner(self)
        return self.monkeyrunner

    def get_view_client(self):
        """
        get view_client connection of the device
        :return:
        """
        if self.view_client_enabled and self.view_client is None:
            kwargs = {'startviewserver': True,
                      'autodump': False,
                      # 'forceviewserveruse': True,
                      'ignoreuiautomatorkilled': True}
            self.view_client = ViewClient(self.adb, self.serial, **kwargs)
        return self.view_client

    def is_foreground(self, app):
        """
        check if app is in foreground of device
        :param app: App
        :return: boolean
        """
        if isinstance(app, str):
            package_name = app
        elif isinstance(app, App):
            package_name = app.get_package_name()
        else:
            return False

        focused_window_name = self.get_adb().getTopActivityName()
        if focused_window_name is None:
            return False
        return focused_window_name.startswith(package_name)

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

        # DOWN skip first-use turorials, we don't have to

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
        return True

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
        return self.send_intent(intent=call_intent)

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
        return True

    def receive_sms(self, phone=DEFAULT_NUM, content=DEFAULT_CONTENT):
        """
        receive a SMS
        :param phone: str, phone number of sender
        :param content: str, content of sms
        :return:
        """
        assert self.get_telnet() is not None
        return self.get_telnet().run_cmd("sms send %s '%s'" % (phone, content))

    def set_gps(self, x, y):
        """
        set GPS positioning to x,y
        :param x: float
        :param y: float
        :return:
        """
        assert self.get_telnet() is not None
        return self.get_telnet().run_cmd("geo fix %s %s" % (x, y))

    def set_continuous_gps(self, center_x, center_y, delta_x, delta_y):
        import threading
        gps_thread = threading.Thread(
            target=self.set_continuous_gps_blocked,
            args=(center_x, center_y, delta_x, delta_y))
        gps_thread.start()
        return True

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
        return True

    def send_intent(self, intent):
        """
        send an intent to device via am (ActivityManager)
        :param intent: instance of Intent
        :return:
        """
        assert self.get_adb() is not None
        assert intent is not None
        cmd = intent.get_cmd()
        return self.get_adb().shell(cmd)

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
        if isinstance(app, str):
            package_name = app
        elif isinstance(app, App):
            package_name = app.get_package_name()
            if app.get_main_activity():
                package_name += "/%s" % app.get_main_activity()
        else:
            self.logger.warning("unsupported param " + app + " with type: ", type(app))
            return
        intent = Intent(suffix=package_name)
        self.send_intent(intent)

    def get_service_names(self):
        """
        get current running services
        :return: list of services
        """
        services = []
        dat = self.get_adb().shell('dumpsys activity services')
        lines = dat.splitlines()
        serviceRE = re.compile('^.+ServiceRecord{.+ ([A-Za-z0-9_.]+)/.([A-Za-z0-9_.]+)}')

        for line in lines:
            m = serviceRE.search(line)
            if m:
                package = m.group(1)
                service = m.group(2)
                services.append("%s/%s" % (package, service))
        return services

    def get_package_path(self, package_name):
        """
        get installation path of a package (app)
        :param package_name:
        :return: package path of app in device
        """
        dat = self.get_adb().shell('pm path %s' % package_name)
        package_path_RE = re.compile('^package:(.+)$')
        m = package_path_RE.match(dat)
        if m:
            path = m.group(1)
            return path.strip()
        return None

    def start_activity_via_monkey(self, package):
        """
        use monkey to start activity
        """
        cmd = 'monkey'
        if package:
            cmd += ' -p %s' % package
        out = self.get_adb().shell(cmd)
        if re.search(r"(Error)|(Cannot find 'App')", out, re.IGNORECASE | re.MULTILINE):
            raise RuntimeError(out)

    def install_app(self, app):
        """
        install an app to device
        @param app: instance of App
        @return:
        """
        assert isinstance(app, App)
        subprocess.check_call(["adb", "uninstall", app.get_package_name()],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.check_call(["adb", "install", app.app_path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        package_info_file_name = "%s/dumpsys_package_%s.txt" % (self.output_dir, app.get_package_name())
        package_info_file = open(package_info_file_name, "w")
        subprocess.check_call(["adb", "shell", "dumpsys", "package", app.get_package_name()], stdout=package_info_file)
        package_info_file.close()

    def uninstall_app(self, app):
        assert isinstance(app, App)
        subprocess.check_call(["adb", "uninstall", app.get_package_name()],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def get_current_state(self):
        self.logger.info("getting current device state...")
        try:
            view_client_views = self.get_view_client().dump()
            foreground_activity = self.get_adb().getTopActivityName()
            background_services = self.get_service_names()
            snapshot = self.get_adb().takeSnapshot(reconnect=True)
            self.logger.info("finish getting current device state...")
            return DeviceState(self,
                               view_client_views=view_client_views,
                               foreground_activity=foreground_activity,
                               background_services=background_services,
                               snapshot=snapshot)
        except Exception as e:
            self.logger.warning(e)
            return None


class DeviceState(object):
    """
    the state of the current device
    """
    def __init__(self, device, view_client_views, foreground_activity, background_services, tag=None, snapshot=None):
        self.device = device
        self.view_client_views = view_client_views
        self.foreground_activity = foreground_activity
        self.background_services = background_services
        if tag is None:
            from datetime import datetime
            tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.tag = tag
        self.snapshot = snapshot
        self.views = self.views2list(view_client_views)

    def to_dict(self):
        state = {'tag': self.tag,
                 'foreground_activity': self.foreground_activity,
                 'background_services': self.background_services,
                 'views': self.views}
        return state

    def to_json(self):
        import json
        return json.dumps(self.to_dict(), indent=2)

    def views2list(self, view_client_views):
        views = []
        view2id_map = {}
        id2view_map = {}
        temp_id = 0
        for view in view_client_views:
            view2id_map[view] = temp_id
            id2view_map[temp_id] = view
            temp_id += 1

        from com.dtmilano.android.viewclient import View
        for view in view_client_views:
            if isinstance(view, View):
                view_dict = view.map
                view_dict['temp_id'] = view2id_map.get(view)
                view_dict['parent'] = view2id_map.get(view.getParent())
                view_dict['children'] = [view2id_map.get(view_child) for view_child in view.getChildren()]
                view_dict['view_str'] = DeviceState.get_view_str(view_dict)
                views.append(view_dict)
        return views

    def save2dir(self, output_dir=None):
        try:
            if output_dir is None:
                output_dir = os.path.join(self.device.output_dir, "device_states")
            if not os.path.exists(output_dir):
                os.mkdir(output_dir)
            state_json_file_path = "%s/device_state_%s.json" % (output_dir, self.tag)
            snapshot_file_path = "%s/snapshot_%s.png" % (output_dir, self.tag)
            state_json_file = open(state_json_file_path, "w")
            state_json_file.write(self.to_json())
            state_json_file.close()
            from PIL.Image import Image
            if isinstance(self.snapshot, Image):
                self.snapshot.save(snapshot_file_path)
        except Exception as e:
            self.device.logger.warning("saving state to dir failed: " + e.message)

    def is_different_from(self, other_state):
        """
        compare this state with another
        @param other_state: DeviceState
        @return: boolean, true if this state is different from other_state
        """
        if self.foreground_activity != other_state.foreground_activity:
            return True
        # ignore background service differences
        # if self.background_services != other_state.background_services:
        #     return True
        this_views = {view['view_str'] for view in self.views}
        other_views = {view['view_str'] for view in other_state.views}
        if this_views != other_views:
            return True
        return False

    @staticmethod
    def get_view_str(view_dict):
        """
        get the unique string which can represent the view
        @param view_dict: dict, element of list device.get_current_state().views
        @return:
        """
        view_str = "package:%s,class:%s,resource-id:%s,text:%s" %\
                   (view_dict['package'], view_dict['class'], view_dict['resource-id'], view_dict['text'])
        return view_str

    @staticmethod
    def get_view_center(view_dict):
        """
        return the center point in a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        return (bounds[0][0]+bounds[1][0])/2, (bounds[0][1]+bounds[1][1])/2

    @staticmethod
    def get_view_size(view_dict):
        """
        return the size of a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        import math
        return int(math.fabs((bounds[0][0]-bounds[1][0])*(bounds[0][1]-bounds[1][1])))

class App(object):
    """
    this class describes an app
    """
    def __init__(self, app_path, output_dir=None):
        """
        create a App instance
        :param app_path: local file path of app
        :return:
        """
        assert app_path is not None
        self.logger = logging.getLogger('App')

        self.app_path = app_path
        self.output_dir = output_dir
        self.androguard = AndroguardAnalysis(self.app_path)
        self.package_name = self.androguard.a.get_package()
        self.main_activity = self.androguard.a.get_main_activity()
        self.possible_broadcasts = self.get_possible_broadcasts()

    def get_androguard_analysis(self):
        """
        run static analysis of app
        :return:get_adb().takeSnapshot(reconnect=True)
        """
        if self.androguard is None:
            self.androguard = AndroguardAnalysis(self.app_path)
        return self.androguard

    def pull_app_from_device(self, device):
        """
        get app file path of current app
        :param device: Device
        :return:
        """
        if self.app_path is not None:
            return self.app_path
        if self.package_name is None:
            self.logger.warning("Trying to get app path without package name")
            return None
        # if we only have package name, use `adb pull` to get the package from device
        try:
            self.logger.info("Trying to pull app(%s) from device to local" % self.package_name)
            app_path_in_device = device.get_package_path(self.package_name)
            app_path = os.path.join(self.output_dir, 'temp', "%s.apk" % self.package_name)
            subprocess.check_call(["adb", "pull", app_path_in_device, app_path])
            self.app_path = app_path
            return self.app_path
        except Exception as e:
            self.logger.warning(e.message)
            return None

    def get_package_name(self):
        """
        get package name of current app
        :return:
        """
        if self.package_name is None:
            self.package_name = self.get_androguard_analysis().a.get_package()
        return self.package_name

    def get_main_activity(self):
        """
        get package name of current app
        :return:
        """
        if self.main_activity is None:
            self.main_activity = self.get_androguard_analysis().a.get_main_activity()
        return self.main_activity

    def get_possible_broadcasts(self):
        possible_broadcasts = set()
        androguard = self.get_androguard_analysis()
        if androguard is None:
            return androguard

        androguard_a = self.get_androguard_analysis().a
        receivers = androguard_a.get_receivers()

        for receiver in receivers:
            intent_filters = androguard_a.get_intent_filters('receiver', receiver)
            if intent_filters.has_key('action'):
                actions = intent_filters['action']
            else:
                actions = []
            if intent_filters.has_key('category'):
                categories = intent_filters['category']
            else:
                categories = []
            categories.append(None)
            for action in actions:
                for category in categories:
                    intent = Intent(prefix='broadcast', action=action, category=category)
                    possible_broadcasts.add(intent)
        return possible_broadcasts

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
        self.app_path = app_path
        from androguard.core.bytecodes.apk import APK
        self.a = APK(app_path)

    def get_detailed_analysis(self):
        from androguard.misc import AnalyzeDex
        self.d, self.dx = AnalyzeDex(self.a.get_dex(), raw=True)


class Intent(object):
    """
    this class describes a intent event
    """
    def __init__(self, prefix="start", action=None, data_uri=None, mime_type=None, category=None,
                 component=None, flag=None, extra_keys=None, extra_string=None, extra_boolean=None,
                 extra_int=None, extra_long=None, extra_float=None, extra_uri=None, extra_component=None,
                 extra_array_int=None, extra_array_long=None, extra_array_float=None, flags=None, suffix=""):
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
