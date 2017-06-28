import logging
import os
import re
import subprocess
import sys
import time

from app import App
from intent import Intent

DEFAULT_NUM = '1234567890'
DEFAULT_CONTENT = 'Hello world!'


class Device(object):
    """
    this class describes a connected device
    """

    def __init__(self, device_serial=None, is_emulator=True, output_dir=None,
                 use_hierarchy_viewer=False, grant_perm=False, telnet_auth_token=None,
                 dont_tear_down=False):
        """
        initialize a device connection
        :param device_serial: serial number of target device
        :param is_emulator: boolean, type of device, True for emulator, False for real device
        :return:
        """
        self.logger = logging.getLogger("Device")

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
        self.use_hierarchy_viewer = use_hierarchy_viewer
        self.grant_perm = grant_perm
        self.telnet_auth_token = telnet_auth_token
        self.dont_tear_down = dont_tear_down

        # Connections
        self.adb = None
        self.telnet = None
        self.view_client = None
        self.droidbot_app = None
        self.minicap = None

        self.adb_enabled = True
        self.telnet_enabled = False
        self.view_client_enabled = False
        self.droidbot_app_enabled = True
        self.minicap_enabled = True

        # if self.is_emulator:
        #     self.telnet_enabled = True

        self.settings = {}
        self.display_info = None
        self.sdk_version = None
        self.release_version = None
        self.ro_debuggable = None
        self.ro_secure = None

        self.logcat = None
        self.getevent = None
        self.process_monitor = None

        self.is_connected = False

    def redirect_logcat(self, output_dir=None):
        if output_dir is None:
            return None
        logcat_file = open("%s/logcat.txt" % output_dir, "w")
        import subprocess
        subprocess.check_call(["adb", "-s", self.serial, "logcat", "-c"])
        logcat = subprocess.Popen(["adb", "-s", self.serial, "logcat", "-v", "threadtime"],
                                  stdin=subprocess.PIPE,
                                  stdout=logcat_file)
        return logcat

    def redirect_input_events(self, output_dir=None):
        if output_dir is None:
            return None
        getevent_file = open("%s/getevent.txt" % output_dir, "w")
        import subprocess
        getevent = subprocess.Popen(["adb", "-s", self.serial, "shell", "getevent", "-lt"],
                                    stdin=subprocess.PIPE,
                                    stdout=getevent_file)
        return getevent

    def check_connectivity(self):
        """
        check if the device is available
        :return: True for available, False for not
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

            if self.view_client_enabled and self.view_client:
                self.logger.info("view_client is connected")
            else:
                self.logger.warning("view_client is not connected")
                result = False

            if self.minicap_enabled and self.minicap and self.minicap.check_connectivity():
                self.logger.info("minicap is connected")
            else:
                self.logger.warning("minicap is not connected")
                result = False

            if self.droidbot_app_enabled and self.droidbot_app and self.droidbot_app.check_connectivity():
                self.logger.info("droidbot_app is connected")
            else:
                self.logger.warning("droidbot_app is not connected")
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
        connect this device
        :return:
        """
        # wait for emulator to start
        self.wait_for_device()
        if self.adb_enabled:
            self.get_adb()

        if self.telnet_enabled:
            self.get_telnet()

        if self.view_client_enabled:
            self.get_view_client()

        if self.droidbot_app_enabled:
            self.get_droidbot_app().connect()

        if self.minicap_enabled:
            self.get_minicap().connect()

        time.sleep(3)

        self.get_sdk_version()
        self.get_release_version()
        self.get_ro_secure()
        self.get_ro_debuggable()
        self.get_display_info()

        self.logcat = self.redirect_logcat(self.output_dir)
        self.getevent = self.redirect_input_events(self.output_dir)
        from adapter.process_monitor import ProcessMonitor
        self.process_monitor = ProcessMonitor(device=self)
        self.process_monitor.start()
        self.unlock()

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
        if self.view_client:
            self.view_client.disconnect()
        if self.logcat:
            self.logcat.terminate()
        if self.getevent:
            self.getevent.terminate()
        if self.droidbot_app:
            self.droidbot_app.disconnect()
        if self.minicap:
            self.minicap.disconnect()
        if self.process_monitor:
            self.process_monitor.stop()

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
            from adapter.telnet import TelnetConsole
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

    def get_view_client(self):
        """
        get view_client connection of the device
        :return:
        """
        if self.view_client_enabled and self.view_client is None:
            from adapter.viewclient import ViewClient
            self.view_client = ViewClient(self, forceviewserveruse=self.use_hierarchy_viewer)
        return self.view_client

    def get_minicap(self):
        """
        get minicap connection
        :return: 
        """
        if self.minicap_enabled and self.minicap is None:
            from adapter.minicap import Minicap
            self.minicap = Minicap(self)
        return self.minicap

    def get_droidbot_app(self):
        """
        get droidbot app connection
        :return: 
        """
        if self.droidbot_app_enabled and self.droidbot_app is None:
            from adapter.droidbot_app import DroidBotAppConn
            self.droidbot_app = DroidBotAppConn(self)
        return self.droidbot_app

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
            self.ro_debuggable = self.get_adb().get_ro_debuggable()
        return self.ro_debuggable

    def get_display_info(self, refresh=True):
        """
        get device display infomation, including width, height, and density
        :param refresh: if set to True, refresh the display info instead of using the old values
        :return: dict, display_info
        """
        if self.display_info is None or refresh:
            self.display_info = self.get_adb().get_display_info()
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

    def shake(self):
        """
        shake the device
        :return: 
        """
        telnet = self.get_telnet()
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

    def get_task_activities(self):
        """
        Get current tasks and corresponding activities.
        :return: a dict with three attributes: task_to_activities, current_task, and top_activity.
        task_to_activities is a dict mapping a task id to a list of activities, from top to down.
        current_task is the id of the active task.
        top_activity is the name of the top activity
        """
        lines = self.get_adb().shell("dumpsys activity activities").splitlines()

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
        dat = self.get_adb().shell('dumpsys activity services')
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
        return self.get_adb().get_focused_window_name()

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
        """
        Uninstall an app from device.
        :param app: an instance of App or a package name
        :return: 
        """
        if isinstance(app, App):
            package_name = app.get_package_name()
        else:
            package_name = app
        subprocess.check_call(["adb", "-s", self.serial, "uninstall", package_name],
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
        local_image_dir = os.path.join(self.output_dir, "temp")
        if not os.path.exists(local_image_dir):
            os.mkdir(local_image_dir)

        if self.get_minicap() is not None:
            last_screen = self.get_minicap().last_screen
            if last_screen is not None:
                local_image_path = os.path.join(local_image_dir, "screen_%s.jpg" % tag)
                f = open(local_image_path, 'w')
                f.write(last_screen)
                f.close()
                return local_image_path

        local_image_path = os.path.join(local_image_dir, "screen_%s.png" % tag)
        remote_image_path = "/sdcard/screen_%s.png" % tag
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
            from state import DeviceState
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
        self.get_adb().long_touch(x, y, duration)

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

    def dump_views(self):
        if self.get_droidbot_app() is not None:
            views = self.get_droidbot_app().get_views()
            if views is not None:
                return views

        return self.get_view_client().dump()
