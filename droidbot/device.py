import logging
import os
import re
import subprocess
import sys
import time

from adapter.adb import ADB
from adapter.droidbot_app import DroidBotAppConn
from adapter.logcat import Logcat
from adapter.minicap import Minicap
from adapter.process_monitor import ProcessMonitor
from adapter.telnet import TelnetConsole
from adapter.user_input_monitor import UserInputMonitor
from adapter.viewclient import ViewClient
from app import App
from intent import Intent

DEFAULT_NUM = '1234567890'
DEFAULT_CONTENT = 'Hello world!'


class Device(object):
    """
    this class describes a connected device
    """

    def __init__(self, device_serial=None, is_emulator=True, output_dir=None,
                 use_hierarchy_viewer=False, grant_perm=False, telnet_auth_token=None):
        """
        initialize a device connection
        :param device_serial: serial number of target device
        :param is_emulator: boolean, type of device, True for emulator, False for real device
        :return:
        """
        self.logger = logging.getLogger("Device")

        # options
        if device_serial is None:
            import utils
            all_devices = utils.get_available_devices()
            if len(all_devices) == 0:
                self.logger.warning("ERROR: No device connected.")
                sys.exit(-1)
            device_serial = all_devices[0]
        self.serial = device_serial
        self.is_emulator = is_emulator
        self.output_dir = output_dir
        if output_dir is not None:
            if not os.path.isdir(output_dir):
                os.mkdir(output_dir)
        self.grant_perm = grant_perm

        # basic device information
        self.settings = {}
        self.display_info = None
        self.sdk_version = None
        self.release_version = None
        self.ro_debuggable = None
        self.ro_secure = None
        self.is_connected = False

        # adapters
        self.adb = ADB(device=self)
        self.telnet = TelnetConsole(device=self, auth_token=telnet_auth_token)
        self.view_client = ViewClient(device=self, forceviewserveruse=use_hierarchy_viewer)
        self.droidbot_app = DroidBotAppConn(device=self)
        self.minicap = Minicap(device=self)
        self.logcat = Logcat(device=self)
        self.user_input_monitor = UserInputMonitor(device=self)
        self.process_monitor = ProcessMonitor(device=self)

        self.adapters = {
            self.adb: True,
            self.telnet: False,
            self.view_client: False,
            self.droidbot_app: True,
            self.minicap: True,
            self.logcat: True,
            self.user_input_monitor: True,
            self.process_monitor: True
        }

        # if self.is_emulator:
        #     self.telnet_enabled = True

    def check_connectivity(self):
        """
        check if the device is available
        """
        for adapter in self.adapters:
            adapter_name = adapter.__class__.__name__
            adapter_enabled = self.adapters[adapter]
            if not adapter_enabled:
                print "[CONNECTIVITY] %s is not enabled." % adapter_name
            else:
                if adapter.check_connectivity():
                    print "[CONNECTIVITY] %s is enabled and connected." % adapter_name
                else:
                    print "[CONNECTIVITY] %s is enabled but not connected." % adapter_name

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

    def set_up(self):
        """
        Set connections on this device
        :return: 
        """
        # wait for emulator to start
        self.wait_for_device()
        for adapter in self.adapters:
            adapter_enabled = self.adapters[adapter]
            if not adapter_enabled:
                continue
            adapter.set_up()

    def connect(self):
        """
        establish connections on this device
        :return:
        """
        for adapter in self.adapters:
            adapter_enabled = self.adapters[adapter]
            if not adapter_enabled:
                continue
            adapter.connect()

        self.get_sdk_version()
        self.get_release_version()
        self.get_ro_secure()
        self.get_ro_debuggable()
        self.get_display_info()

        self.unlock()
        self.check_connectivity()
        self.is_connected = True

    def disconnect(self):
        """
        disconnect current device
        :return:
        """
        self.is_connected = False
        for adapter in self.adapters:
            adapter_enabled = self.adapters[adapter]
            if not adapter_enabled:
                continue
            adapter.disconnect()

        if self.output_dir is not None:
            temp_dir = os.path.join(self.output_dir, "temp")
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)

    def tear_down(self):
        for adapter in self.adapters:
            adapter_enabled = self.adapters[adapter]
            if not adapter_enabled:
                continue
            adapter.tear_down()

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
            self.sdk_version = self.adb.get_sdk_version()
        return self.sdk_version

    def get_release_version(self):
        """
        Get version of current SDK
        """
        if self.release_version is None:
            self.release_version = self.adb.get_release_version()
        return self.release_version

    def get_ro_secure(self):
        if self.ro_secure is None:
            self.ro_secure = self.adb.get_ro_secure()
        return self.ro_secure

    def get_ro_debuggable(self):
        if self.ro_debuggable is None:
            self.ro_debuggable = self.adb.get_ro_debuggable()
        return self.ro_debuggable

    def get_display_info(self, refresh=True):
        """
        get device display infomation, including width, height, and density
        :param refresh: if set to True, refresh the display info instead of using the old values
        :return: dict, display_info
        """
        if self.display_info is None or refresh:
            self.display_info = self.adb.get_display_info()
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
        self.adb.unlock()

    def shake(self):
        """
        shake the device
        :return: 
        """
        telnet = self.telnet
        if telnet is None:
            self.logger.warning("Telnet not connected, so can't shake the device.")
        l2h = range(0, 11)
        h2l = range(0, 11)
        h2l.reverse()
        sensor_xyz = [(-float(v * 10) + 1, float(v) + 9.8, float(v * 2) + 0.5) for v in [1, -1, 1, -1, 1, -1, 0]]
        for (x, y, z) in sensor_xyz:
            telnet.run_cmd("sensor set acceleration %f:%f:%f" % (x, y, z))

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
        assert self.adb is not None
        contact_intent = Intent(prefix="start",
                                action="android.intent.action.INSERT",
                                mime_type="vnd.android.cursor.dir/contact",
                                extra_string=contact_data)
        self.send_intent(intent=contact_intent)
        time.sleep(2)
        self.adb.press("BACK")
        time.sleep(2)
        self.adb.press("BACK")
        return True

    def receive_call(self, phone=DEFAULT_NUM):
        """
        simulate a income phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.telnet is not None
        return self.telnet.run_cmd("gsm call %s" % phone)

    def cancel_call(self, phone=DEFAULT_NUM):
        """
        cancel phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.telnet is not None
        return self.telnet.run_cmd("gsm cancel %s" % phone)

    def accept_call(self, phone=DEFAULT_NUM):
        """
        accept phonecall
        :param phone: str, phonenum
        :return:
        """
        assert self.telnet is not None
        return self.telnet.run_cmd("gsm accept %s" % phone)

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
        self.adb.press('66')
        return True

    def receive_sms(self, phone=DEFAULT_NUM, content=DEFAULT_CONTENT):
        """
        receive a SMS
        :param phone: str, phone number of sender
        :param content: str, content of sms
        :return:
        """
        assert self.telnet is not None
        return self.telnet.run_cmd("sms send %s '%s'" % (phone, content))

    def set_gps(self, x, y):
        """
        set GPS positioning to x,y
        :param x: float
        :param y: float
        :return:
        """
        assert self.telnet is not None
        return self.telnet.run_cmd("geo fix %s %s" % (x, y))

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
        out = self.adb.shell("sqlite3 %s \"select * from %s\"" % (db_name, "system"))
        out_lines = out.splitlines()
        for line in out_lines:
            segs = line.split('|')
            if len(segs) != 3:
                continue
            system_settings[segs[1]] = segs[2]

        secure_settings = {}
        out = self.adb.shell("sqlite3 %s \"select * from %s\"" % (db_name, "secure"))
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

        self.adb.shell("sqlite3 %s \"update '%s' set value='%s' where name='%s'\""
                       % (db_name, table_name, value, name))
        return True

    def send_intent(self, intent):
        """
        send an intent to device via am (ActivityManager)
        :param intent: instance of Intent
        :return:
        """
        assert self.adb is not None
        assert intent is not None
        if isinstance(intent, Intent):
            cmd = intent.get_cmd()
        else:
            cmd = intent
        return self.adb.shell(cmd)

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
        data = self.adb.shell("dumpsys activity top").splitlines()
        regex = re.compile("\s*ACTIVITY ([A-Za-z0-9_.]+)/([A-Za-z0-9_.]+)")
        m = regex.search(data[1])
        if m:
            return m.group(1) + "/" + m.group(2)
        return None

    def get_task_activities(self):
        """
        Get current tasks and corresponding activities.
        :return: a dict with three attributes: task_to_activities, current_task, and top_activity.
        task_to_activities is a dict mapping a task id to a list of activities, from top to down.
        current_task is the id of the active task.
        top_activity is the name of the top activity
        """
        lines = self.adb.shell("dumpsys activity activities").splitlines()

        result = {}
        task_to_activities = {}

        activity_line_re = re.compile('\* Hist #\d+: ActivityRecord{[^ ]+ [^ ]+ ([^ ]+) t(\d+)}')
        focused_activity_line_re = re.compile('mFocusedActivity: ActivityRecord{[^ ]+ [^ ]+ ([^ ]+) t(\d+)}')

        for line in lines:
            line = line.strip()
            if line.startswith("Task id #"):
                task_id = line[9:]
                task_to_activities[task_id] = []
            elif line.startswith("* Hist #"):
                m = activity_line_re.match(line)
                if m:
                    activity = m.group(1)
                    task_id = m.group(2)
                    if task_id not in task_to_activities:
                        task_to_activities[task_id] = []
                    task_to_activities[task_id].append(activity)
            elif line.startswith("mFocusedActivity: "):
                m = focused_activity_line_re.match(line)
                if m:
                    activity = m.group(1)
                    task_id = m.group(2)
                    result['current_task'] = task_id
                    result['top_activity'] = activity

        result['task_to_activities'] = task_to_activities
        return result

    def get_service_names(self):
        """
        get current running services
        :return: list of services
        """
        services = []
        dat = self.adb.shell('dumpsys activity services')
        lines = dat.splitlines()
        service_re = re.compile('^.+ServiceRecord{.+ ([A-Za-z0-9_.]+)/([A-Za-z0-9_.]+)}')

        for line in lines:
            m = service_re.search(line)
            if m:
                package = m.group(1)
                service = m.group(2)
                services.append("%s/%s" % (package, service))
        return services

    def get_focused_window_name(self):
        return self.adb.get_focused_window_name()

    def get_package_path(self, package_name):
        """
        get installation path of a package (app)
        :param package_name:
        :return: package path of app in device
        """
        dat = self.adb.shell('pm path %s' % package_name)
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
        out = self.adb.shell(cmd)
        if re.search(r"(Error)|(Cannot find 'App')", out, re.IGNORECASE | re.MULTILINE):
            raise RuntimeError(out)

    def install_app(self, app):
        """
        install an app to device
        @param app: instance of App
        @return:
        """
        assert isinstance(app, App)
        # subprocess.check_call(["adb", "-s", self.serial, "uninstall", app.get_package_name()],
        #                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        install_cmd = ["adb", "-s", self.serial, "install", "-r"]
        if self.grant_perm:
            install_cmd.append("-g")
        install_cmd.append(app.app_path)
        subprocess.check_call(install_cmd, stdout=subprocess.PIPE)

        package_name = app.get_package_name()
        dumpsys_p = subprocess.Popen(["adb", "-s", self.serial, "shell",
                                      "dumpsys", "package", package_name], stdout=subprocess.PIPE)
        dumpsys_lines = []
        while True:
            line = dumpsys_p.stdout.readline()
            if not line:
                break
            dumpsys_lines.append(line)

        main_activity = self.__parse_main_activity_from_dumpsys_lines(dumpsys_lines)
        self.logger.info("App installed: %s/%s" % (package_name, main_activity))

        app.dumpsys_main_activity = main_activity

        if self.output_dir is not None:
            package_info_file_name = "%s/dumpsys_package_%s.txt" % (self.output_dir, app.get_package_name())
            package_info_file = open(package_info_file_name, "w")
            package_info_file.writelines(dumpsys_lines)
            package_info_file.close()

    @staticmethod
    def __parse_main_activity_from_dumpsys_lines(lines):
        main_activity = None
        activity_line_re = re.compile("[^ ]+ ([^ ]+)/([^ ]+) filter [^ ]+")
        action_re = re.compile("Action: \"([^ ]+)\"")
        category_re = re.compile("Category: \"([^ ]+)\"")

        activities = {}

        cur_package = None
        cur_activity = None
        cur_actions = []
        cur_categories = []

        for line in lines:
            line = line.strip()
            m = activity_line_re.match(line)
            if m:
                activities[cur_activity] = {
                    "actions": cur_actions,
                    "categories": cur_categories
                }
                cur_package = m.group(1)
                cur_activity = m.group(2)
                if cur_activity.startswith("."):
                    cur_activity = cur_package + cur_activity
                cur_actions = []
                cur_categories = []
            else:
                m1 = action_re.match(line)
                if m1:
                    cur_actions.append(m1.group(1))
                else:
                    m2 = category_re.match(line)
                    if m2:
                        cur_categories.append(m2.group(1))

        if cur_activity is not None:
            activities[cur_activity] = {
                "actions": cur_actions,
                "categories": cur_categories
            }

        for activity in activities:
            if "android.intent.action.MAIN" in activities[activity]["actions"] \
                    and "android.intent.category.LAUNCHER" in activities[activity]["categories"]:
                main_activity = activity
        return main_activity

    def uninstall_app(self, app):
        """
        Uninstall an app from device.
        :param app: an instance of App or a package name
        :return: 
        """
        if isinstance(app, App):
            package_name = app.get_package_name()
        else:
            package_name = app
        if package_name in self.adb.get_installed_apps():
            subprocess.check_call(["adb", "-s", self.serial, "uninstall", package_name], stdout=subprocess.PIPE)

    def get_app_pid(self, app):
        if isinstance(app, App):
            package = app.get_package_name()
        else:
            package = app

        name2pid = {}
        ps_out = self.adb.shell(["ps", "-t"])
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
        self.adb.run_cmd(["push", local_file, remote_dir])

    def pull_file(self, remote_file, local_file):
        self.adb.run_cmd(["pull", remote_file, local_file])

    def take_screenshot(self):
        # image = None
        #
        # received = self.adb.shell("screencap -p").replace("\r\n", "\n")
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
        local_image_dir = os.path.join(self.output_dir, "temp")
        if not os.path.exists(local_image_dir):
            os.mkdir(local_image_dir)

        if self.minicap is not None:
            last_screen = self.minicap.last_screen
            if last_screen is not None:
                local_image_path = os.path.join(local_image_dir, "screen_%s.jpg" % tag)
                f = open(local_image_path, 'w')
                f.write(last_screen)
                f.close()
                return local_image_path

        local_image_path = os.path.join(local_image_dir, "screen_%s.png" % tag)
        remote_image_path = "/sdcard/screen_%s.png" % tag
        self.adb.shell("screencap -p %s" % remote_image_path)
        self.pull_file(remote_image_path, local_image_path)
        self.adb.shell("rm %s" % remote_image_path)

        return local_image_path

    def get_current_state(self):
        self.logger.info("getting current device state...")
        current_state = None
        try:
            view_client_views = self.get_views()
            foreground_activity = self.get_top_activity_name()
            background_services = self.get_service_names()
            screenshot_path = self.take_screenshot()
            self.logger.debug("finish getting current device state...")
            from device_state import DeviceState
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
        self.adb.touch(x, y)

    def view_long_touch(self, x, y, duration=2000):
        """
        Long touches at (x, y)
        @param duration: duration in ms
        This workaround was suggested by U{HaMi<http://stackoverflow.com/users/2571957/hami>}
        """
        self.adb.long_touch(x, y, duration)

    def view_drag(self, (x0, y0), (x1, y1), duration):
        """
        Sends drag event n PX (actually it's using C{input swipe} command.
        @param (x0, y0): starting point in PX
        @param (x1, y1): ending point in PX
        @param duration: duration of the event in ms
        """
        self.adb.drag((x0, y0), (x1, y1), duration)

    def view_input_text(self, text):
        self.adb.type(text)

    def key_press(self, key_code):
        self.adb.press(key_code)

    def get_views(self):
        if self.droidbot_app is not None:
            views = self.droidbot_app.get_views()
            if views is not None:
                return views

        return self.view_client.dump()
