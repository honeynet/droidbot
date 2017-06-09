import logging
import os
import re
import subprocess
import time

from app import App
from intent import Intent

DEFAULT_NUM = '1234567890'
DEFAULT_CONTENT = 'Hello world!'


class Device(object):
    """
    this class describes a connected device
    """

    def __init__(self, device_serial, is_emulator=True, output_dir=None,
                 use_hierarchy_viewer=False, grant_perm=False):
        """
        create a device
        :param device_serial: serial number of target device
        :param is_emulator: boolean, type of device, True for emulator, False for real device
        :return:
        """
        self.logger = logging.getLogger("Device")

        self.serial = device_serial
        self.is_emulator = is_emulator
        self.adb = None
        self.telnet = None
        self.monkeyrunner = None
        self.view_client = None
        self.settings = {}
        self.display_info = None
        self.sdk_version = None
        self.release_version = None
        self.ro_debuggable = None
        self.ro_secure = None

        self.output_dir = output_dir
        if output_dir is not None:
            if not os.path.isdir(output_dir):
                os.mkdir(output_dir)

        self.use_hierarchy_viewer = use_hierarchy_viewer
        self.grant_perm = grant_perm

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
        self.get_sdk_version()
        self.get_release_version()
        self.get_ro_secure()
        self.get_ro_debuggable()
        self.get_display_info()
        self.logcat = self.redirect_logcat(self.output_dir)
        from state_monitor import StateMonitor
        self.state_monitor = StateMonitor(device=self)
        self.state_monitor.start()
        self.unlock()
        # assert self.display_info is not None
        # self.check_connectivity()
        # print self.is_emulator, self.host, self.port

    def redirect_logcat(self, output_dir=None):
        if output_dir is None:
            return None
        logcat_file = open("%s/logcat.log" % output_dir, "w")
        import subprocess
        subprocess.check_call(["adb", "-s", self.serial, "logcat", "-c"])
        logcat = subprocess.Popen(["adb", "-s", self.serial, "logcat", "-v", "threadtime"],
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

    def wait_for_device(self):
        """
        wait until the device is fully booted
        :return:
        """
        self.logger.info("waiting for device")
        try:
            subprocess.check_call(["adb", "-s", self.serial, "wait-for-device"])
            while True:
                out = subprocess.check_output(["adb", "-s", self.serial, "shell",
                                               "getprop", "init.svc.bootanim"]).split()[0]
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
            self.view_client.disconnect()
        if self.logcat:
            self.logcat.terminate()
        self.state_monitor.stop()

        if self.output_dir is not None:
            temp_dir = os.path.join(self.output_dir, "temp")
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)

    def get_telnet(self):
        """
        get telnet connection of the device
        note that only emulator have telnet connection
        """
        if self.telnet_enabled and self.telnet is None:
            from adapter.telnet import TelnetConsole, TelnetException
            try:
                self.telnet = TelnetConsole(self)
            except Exception:
                self.logger.info("Telnet not connected. If you want to enable telnet, please use an emulator.")
        return self.telnet

    def get_adb(self):
        """
        get adb connection of the device
        """
        if self.adb_enabled and self.adb is None:
            from adapter.adb import ADB
            self.adb = ADB(self)
        return self.adb

    def get_monkeyrunner(self):
        """
        get monkeyrunner connection of the device
        :return:
        """
        if self.monkeyrunner_enabled and self.monkeyrunner is None:
            from adapter.monkey_runner import MonkeyRunner
            self.monkeyrunner = MonkeyRunner(self)
        return self.monkeyrunner

    def get_view_client(self):
        """
        get view_client connection of the device
        :return:
        """
        if self.view_client_enabled and self.view_client is None:
            from adapter.viewclient import ViewClient
            self.view_client = ViewClient(self, forceviewserveruse=self.use_hierarchy_viewer)
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

        top_activity_name = self.get_top_activity_name()
        if top_activity_name is None:
            return False
        return top_activity_name.startswith(package_name)

    def get_sdk_version(self):
        """
        Get version of current SDK
        """
        if self.sdk_version is None:
            self.sdk_version = self.get_adb().get_sdk_version()
        return self.sdk_version

    def get_release_version(self):
        """
        Get version of current SDK
        """
        if self.release_version is None:
            self.release_version = self.get_adb().get_release_version()
        return self.release_version

    def get_ro_secure(self):
        if self.ro_secure is None:
            self.ro_secure = self.get_adb().get_ro_secure()
        return self.ro_secure

    def get_ro_debuggable(self):
        if self.ro_debuggable is None:
            self.ro_debuggable = self.get_adb().get_release_version()
        return self.ro_debuggable

    def get_display_info(self, refresh=True):
        """
        get device display infomation, including width, height, and density
        :return: dict, display_info
        @param refresh: if set to True, refresh the display info instead of using the old values
        """
        if self.display_info is None or refresh:
            self.display_info = self.get_adb().getDisplayInfo()
        return self.display_info

    def get_width(self, refresh=False):
        display_info = self.get_display_info(refresh=refresh)
        width = 0
        if "width" in display_info:
            width = display_info["width"]
        elif not refresh:
            width = self.get_width(refresh=True)
        else:
            self.logger.warning("get_width: width not in display_info")
        return width

    def get_height(self, refresh=False):
        display_info = self.get_display_info(refresh=refresh)
        height = 0
        if "height" in display_info:
            height = display_info["height"]
        elif not refresh:
            height = self.get_width(refresh=True)
        else:
            self.logger.warning("get_height: height not in display_info")
        return height

    def unlock(self):
        """
        unlock screen
        skip first-use tutorials
        etc
        :return:
        """
        assert self.get_adb() is not None

        # unlock screen
        self.get_adb().unlock()

        # DONE skip first-use turorials, we don't have to

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
                                 extra_string={'sms_body': content},
                                 extra_boolean={'exit_on_sent': 'true'})
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
        @param center_x: x coordinate of GPS position
        @param center_y: y coordinate of GPS position
        @param delta_x: range of x coordinate
        @param delta_y: range of y coordinate
        """
        import random
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
        for line in out_lines:
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
        if isinstance(intent, Intent):
            cmd = intent.get_cmd()
        else:
            cmd = intent
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

    def get_top_activity_name(self):
        """
        Get current activity
        """
        data = self.get_adb().shell("dumpsys activity top").splitlines()
        regex = re.compile("\s*ACTIVITY ([A-Za-z0-9_.]+)/([A-Za-z0-9_.]+)")
        m = regex.search(data[1])
        if m:
            return m.group(1) + "/" + m.group(2)
        return None

    def get_service_names(self):
        """
        get current running services
        :return: list of services
        """
        services = []
        dat = self.get_adb().shell('dumpsys activity services')
        lines = dat.splitlines()
        service_re = re.compile('^.+ServiceRecord{.+ ([A-Za-z0-9_.]+)/.([A-Za-z0-9_.]+)}')

        for line in lines:
            m = service_re.search(line)
            if m:
                package = m.group(1)
                service = m.group(2)
                services.append("%s/%s" % (package, service))
        return services

    def get_focused_window_name(self):
        return self.get_adb().getFocusedWindowName()

    def get_package_path(self, package_name):
        """
        get installation path of a package (app)
        :param package_name:
        :return: package path of app in device
        """
        dat = self.get_adb().shell('pm path %s' % package_name)
        package_path_re = re.compile('^package:(.+)$')
        m = package_path_re.match(dat)
        if m:
            path = m.group(1)
            return path.strip()
        return None

    def start_activity_via_monkey(self, package):
        """
        use monkey to start activity
        @param package: package name of target activity
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
        subprocess.check_call(["adb", "-s", self.serial, "uninstall", app.get_package_name()],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        install_cmd = ["adb", "-s", self.serial, "install"]
        if self.grant_perm:
            install_cmd.append("-g")
        install_cmd.append(app.app_path)
        subprocess.check_call(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if self.output_dir is not None:
            package_info_file_name = "%s/dumpsys_package_%s.txt" % (self.output_dir, app.get_package_name())
            package_info_file = open(package_info_file_name, "w")
        else:
            package_info_file = subprocess.PIPE

        subprocess.check_call(["adb", "-s", self.serial, "shell", "dumpsys", "package",
                               app.get_package_name()], stdout=package_info_file)

        if isinstance(package_info_file, file):
            package_info_file.close()

    def uninstall_app(self, app):
        assert isinstance(app, App)
        subprocess.check_call(["adb", "-s", self.serial, "uninstall", app.get_package_name()],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def get_app_pid(self, app):
        package = app.get_package_name()

        name2pid = {}
        ps_out = self.get_adb().shell(["ps", "-t"])
        ps_out_lines = ps_out.splitlines()
        ps_out_head = ps_out_lines[0].split()
        if ps_out_head[1] != "PID" or ps_out_head[-1] != "NAME":
            self.logger.warning("ps command output format error: %s" % ps_out_head)
        for ps_out_line in ps_out_lines[1:]:
            segs = ps_out_line.split()
            if len(segs) < 4:
                continue
            pid = int(segs[1])
            name = segs[-1]
            name2pid[name] = pid

        if package in name2pid:
            return name2pid[package]

        possible_pids = []
        for name in name2pid:
            if name.startswith(package):
                possible_pids.append(name2pid[name])
        if len(possible_pids) > 0:
            return min(possible_pids)

        return None

    def push_file(self, local_file, remote_dir="/sdcard/"):
        """
        push file/directory to target_dir
        :param local_file: path to file/directory in host machine
        :param remote_dir: path to target directory in device
        :return:
        """
        if not os.path.exists(local_file):
            self.logger.warning("push_file file does not exist: %s" % local_file)
        self.get_adb().run_cmd(["push", local_file, remote_dir])

    def pull_file(self, remote_file, local_file):
        self.get_adb().run_cmd(["pull", remote_file, local_file])

    def take_screenshot(self):
        # image = None
        #
        # received = self.get_adb().shell("screencap -p").replace("\r\n", "\n")
        # import StringIO
        # stream = StringIO.StringIO(received)
        #
        # try:
        #     from PIL import Image
        #     image = Image.open(stream)
        # except IOError as e:
        #     self.logger.warning("exception in take_screenshot: %s" % e)
        # return image
        if self.output_dir is None:
            return None

        from datetime import datetime
        tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")

        remote_image_path = "/sdcard/screen_%s.png" % tag
        local_image_dir = os.path.join(self.output_dir, "temp")
        if not os.path.exists(local_image_dir):
            os.mkdir(local_image_dir)
        local_image_path = os.path.join(local_image_dir, "screen_%s.png" % tag)

        self.get_adb().shell("screencap -p %s" % remote_image_path)
        self.pull_file(remote_image_path, local_image_path)
        self.get_adb().shell("rm %s" % remote_image_path)

        return local_image_path

    def get_current_state(self):
        self.logger.info("getting current device state...")
        current_state = None
        try:
            view_client_views = self.dump_views()
            foreground_activity = self.get_top_activity_name()
            background_services = self.get_service_names()
            screenshot_path = self.take_screenshot()
            self.logger.info("finish getting current device state...")
            current_state = DeviceState(self,
                                        view_client_views=view_client_views,
                                        foreground_activity=foreground_activity,
                                        background_services=background_services,
                                        screenshot_path=screenshot_path)
        except Exception as e:
            self.logger.warning("exception in get_current_state: %s" % e)
            import traceback
            traceback.print_exc()
        return current_state

    def view_touch(self, x, y):
        self.get_adb().touch(x, y)

    def view_long_touch(self, x, y, duration=2000):
        """
        Long touches at (x, y)
        @param duration: duration in ms
        This workaround was suggested by U{HaMi<http://stackoverflow.com/users/2571957/hami>}
        """
        self.get_adb().longTouch(x, y, duration)

    def view_drag(self, (x0, y0), (x1, y1), duration):
        """
        Sends drag event n PX (actually it's using C{input swipe} command.
        @param (x0, y0): starting point in PX
        @param (x1, y1): ending point in PX
        @param duration: duration of the event in ms
        """
        self.get_adb().drag((x0, y0), (x1, y1), duration)

    def view_input_text(self, text):
        self.get_adb().type(text)

    def key_press(self, key_code):
        self.get_adb().press(key_code)

    def dump_views(self, focused_window=True):
        return self.get_view_client().dump()


class DeviceState(object):
    """
    the state of the current device
    """

    def __init__(self, device, view_client_views, foreground_activity, background_services, tag=None, screenshot_path=None):
        self.device = device
        self.view_client_views = view_client_views
        self.foreground_activity = foreground_activity
        self.background_services = background_services
        if tag is None:
            from datetime import datetime
            tag = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.tag = tag
        self.screenshot_path = screenshot_path
        self.views = self.views2list(view_client_views)
        self.view_str = self.get_state_str()

    def to_dict(self):
        state = {'tag': self.tag,
                 'view_str': self.view_str,
                 'foreground_activity': self.foreground_activity,
                 'background_services': self.background_services,
                 'views': self.views}
        return state

    def to_json(self):
        import json
        return json.dumps(self.to_dict(), indent=2)

    @staticmethod
    def views2list(view_client_views):
        views = []
        view2id_map = {}
        id2view_map = {}
        temp_id = 0
        for view in view_client_views:
            view2id_map[view] = temp_id
            id2view_map[temp_id] = view
            temp_id += 1

        from adapter.viewclient import View
        for view in view_client_views:
            if isinstance(view, View):
                view_dict = {}
                view_dict['class'] = view.getClass() #None is possible value
                view_dict['text'] = view.getText() #None is possible value
                view_dict['resource_id'] = view.getId() #None is possible value
                view_dict['temp_id'] = view2id_map.get(view)
                view_dict['parent'] = view2id_map.get(view.getParent()) #None is possible value
                view_dict['children'] = [view2id_map.get(view_child) for view_child in view.getChildren()]
                view_dict['enabled'] = view.isEnabled()
                view_dict['focused'] = view.isFocused()
                view_dict['bounds'] = view.getBounds()
                view_dict['size'] = "%d*%d" % (view.getWidth(), view.getHeight())
                view_dict['view_str'] = DeviceState.get_view_str(view_dict)

                views.append(view_dict)
        return views

    def get_state_str(self):
        state_str = "activity:%s," % self.foreground_activity
        view_ids = set()
        for view in self.views:
            view_id = view['resource_id']
            if view_id is None or len(view_id) == 0:
                continue
            view_ids.add(view_id)
        state_str += ",".join(sorted(view_ids))
        return state_str

    def save2dir(self, output_dir=None):
        try:
            if output_dir is None:
                if self.device.output_dir is None:
                    return
                else:
                    output_dir = os.path.join(self.device.output_dir, "states")
            if not os.path.exists(output_dir):
                os.mkdir(output_dir)
            state_json_file_path = "%s/state_%s.json" % (output_dir, self.tag)
            screenshot_output_path = "%s/screenshot_%s.png" % (output_dir, self.tag)
            state_json_file = open(state_json_file_path, "w")
            state_json_file.write(self.to_json())
            state_json_file.close()
            subprocess.check_call(["cp", self.screenshot_path, screenshot_output_path])
            # from PIL.Image import Image
            # if isinstance(self.screenshot_path, Image):
            #     self.screenshot_path.save(screenshot_output_path)
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
        view_str = "class:%s,resource_id:%s,size:%s,text:%s" % \
                   (view_dict['class'] if 'class' in view_dict else 'null',
                    view_dict['resource_id'] if 'resource_id' in view_dict else 'null',
                    view_dict['size'] if 'size' in view_dict else 'null',
                    view_dict['text'] if 'text' in view_dict else 'null')
        return view_str

    @staticmethod
    def get_view_center(view_dict):
        """
        return the center point in a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        return (bounds[0][0] + bounds[1][0]) / 2, (bounds[0][1] + bounds[1][1]) / 2

    @staticmethod
    def get_view_size(view_dict):
        """
        return the size of a view
        @param view_dict: dict, element of device.get_current_state().views
        @return:
        """
        bounds = view_dict['bounds']
        import math
        return int(math.fabs((bounds[0][0] - bounds[1][0]) * (bounds[0][1] - bounds[1][1])))
