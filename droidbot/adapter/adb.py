# This is the interface for adb
import subprocess
import logging
import re
from .adapter import Adapter
import time


class ADBException(Exception):
    """
    Exception in ADB connection
    """
    pass


class ADB(Adapter):
    """
    interface of ADB
    send adb commands via this, see:
    http://developer.android.com/tools/help/adb.html
    """
    UP = 0
    DOWN = 1
    DOWN_AND_UP = 2
    MODEL_PROPERTY = "ro.product.model"
    VERSION_SDK_PROPERTY = 'ro.build.version.sdk'
    VERSION_RELEASE_PROPERTY = 'ro.build.version.release'
    RO_SECURE_PROPERTY = 'ro.secure'
    RO_DEBUGGABLE_PROPERTY = 'ro.debuggable'

    def __init__(self, device=None):
        """
        initiate a ADB connection from serial no
        the serial no should be in output of `adb devices`
        :param device: instance of Device
        :return:
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        if device is None:
            from droidbot.device import Device
            device = Device()
        self.device = device

        self.cmd_prefix = ['adb', "-s", device.serial]

    def run_cmd(self, extra_args):
        """
        run an adb command and return the output
        :return: output of adb command
        @param extra_args: arguments to run in adb
        """
        if isinstance(extra_args, str) or isinstance(extra_args, str):
            extra_args = extra_args.split()
        if not isinstance(extra_args, list):
            msg = "invalid arguments: %s\nshould be list or str, %s given" % (extra_args, type(extra_args))
            self.logger.warning(msg)
            raise ADBException(msg)

        args = [] + self.cmd_prefix
        args += extra_args

        self.logger.debug('command:')
        self.logger.debug(args)
        r = subprocess.check_output(args).strip()
        if not isinstance(r, str):
            r = r.decode()
        self.logger.debug('return:')
        self.logger.debug(r)
        return r

    def shell(self, extra_args):
        """
        run an `adb shell` command
        @param extra_args:
        @return: output of adb shell command
        """
        if isinstance(extra_args, str) or isinstance(extra_args, str):
            extra_args = extra_args.split()
        if not isinstance(extra_args, list):
            msg = "invalid arguments: %s\nshould be list or str, %s given" % (extra_args, type(extra_args))
            self.logger.warning(msg)
            raise ADBException(msg)

        shell_extra_args = ['shell'] + extra_args
        return self.run_cmd(shell_extra_args)

    def check_connectivity(self):
        """
        check if adb is connected
        :return: True for connected
        """
        r = self.run_cmd("get-state")
        return r.startswith("device")

    def connect(self):
        """
        connect adb
        """
        self.logger.debug("connected")

    def disconnect(self):
        """
        disconnect adb
        """
        print("[CONNECTION] %s is disconnected" % self.__class__.__name__)

    def get_property(self, property_name):
        """
        get the value of property
        @param property_name:
        @return:
        """
        return self.shell(["getprop", property_name])

    def get_model_number(self):
        """
        Get device model number. e.g. SM-G935F
        """
        return self.get_property(ADB.MODEL_PROPERTY)

    def get_sdk_version(self):
        """
        Get version of SDK, e.g. 18, 20
        """
        return int(self.get_property(ADB.VERSION_SDK_PROPERTY))

    def get_release_version(self):
        """
        Get release version, e.g. 4.3, 6.0
        """
        return self.get_property(ADB.VERSION_RELEASE_PROPERTY)

    def get_ro_secure(self):
        """
        get ro.secure value
        @return: 0/1
        """
        return int(self.get_property(ADB.RO_SECURE_PROPERTY))

    def get_ro_debuggable(self):
        """
        get ro.debuggable value
        @return: 0/1
        """
        return int(self.get_property(ADB.RO_DEBUGGABLE_PROPERTY))

    # The following methods are originally from androidviewclient project.
    # https://github.com/dtmilano/AndroidViewClient.
    def get_display_info(self):
        """
        Gets C{mDefaultViewport} and then C{deviceWidth} and C{deviceHeight} values from dumpsys.
        This is a method to obtain display dimensions and density
        """
        display_info = {}
        logical_display_re = re.compile(".*DisplayViewport{valid=true, .*orientation=(?P<orientation>\d+),"
                                        " .*deviceWidth=(?P<width>\d+), deviceHeight=(?P<height>\d+).*")
        dumpsys_display_result = self.shell("dumpsys display")
        if dumpsys_display_result is not None:
            for line in dumpsys_display_result.splitlines():
                m = logical_display_re.search(line, 0)
                if m:
                    for prop in ['width', 'height', 'orientation']:
                        display_info[prop] = int(m.group(prop))

        if 'width' not in display_info or 'height' not in display_info:
            physical_display_re = re.compile('Physical size: (?P<width>\d+)x(?P<height>\d+)')
            m = physical_display_re.search(self.shell('wm size'))
            if m:
                for prop in ['width', 'height']:
                    display_info[prop] = int(m.group(prop))

        if 'width' not in display_info or 'height' not in display_info:
            # This could also be mSystem or mOverscanScreen
            display_re = re.compile('\s*mUnrestrictedScreen=\((?P<x>\d+),(?P<y>\d+)\) (?P<width>\d+)x(?P<height>\d+)')
            # This is known to work on older versions (i.e. API 10) where mrestrictedScreen is not available
            display_width_height_re = re.compile('\s*DisplayWidth=(?P<width>\d+) *DisplayHeight=(?P<height>\d+)')
            for line in self.shell('dumpsys window').splitlines():
                m = display_re.search(line, 0)
                if not m:
                    m = display_width_height_re.search(line, 0)
                if m:
                    for prop in ['width', 'height']:
                        display_info[prop] = int(m.group(prop))

        if 'orientation' not in display_info:
            surface_orientation_re = re.compile("SurfaceOrientation:\s+(\d+)")
            output = self.shell("dumpsys input")
            m = surface_orientation_re.search(output)
            if m:
                display_info['orientation'] = int(m.group(1))

        density = None
        float_re = re.compile(r"[-+]?\d*\.\d+|\d+")
        d = self.get_property('ro.sf.lcd_density')
        if float_re.match(d):
            density = float(d)
        else:
            d = self.get_property('qemu.sf.lcd_density')
            if float_re.match(d):
                density = float(d)
            else:
                physical_density_re = re.compile('Physical density: (?P<density>[\d.]+)', re.MULTILINE)
                m = physical_density_re.search(self.shell('wm density'))
                if m:
                    density = float(m.group('density'))
        if density is not None:
            display_info['density'] = density

        display_info_keys = {'width', 'height', 'orientation', 'density'}
        if not display_info_keys.issuperset(display_info):
            self.logger.warning("getDisplayInfo failed to get: %s" % display_info_keys)

        return display_info

    def get_enabled_accessibility_services(self):
        """
        Get enabled accessibility services
        :return: the enabled service names, each service name is in <package_name>/<service_name> format
        """
        r = self.shell("settings get secure enabled_accessibility_services")
        r = re.sub(r'(?m)^WARNING:.*\n?', '', r)
        return r.strip().split(":") if r.strip() != '' else []

    def disable_accessibility_service(self, service_name):
        """
        Disable an accessibility service
        :param service_name: the service to disable, in <package_name>/<service_name> format
        """
        service_names = self.get_enabled_accessibility_services()
        if service_name in service_names:
            service_names.remove(service_name)
            self.shell("settings put secure enabled_accessibility_services %s" % ":".join(service_names))

    def enable_accessibility_service(self, service_name):
        """
        Enable an accessibility service
        :param service_name: the service to enable, in <package_name>/<service_name> format
        """
        service_names = self.get_enabled_accessibility_services()
        if service_name not in service_names:
            service_names.append(service_name)
            self.shell("settings put secure enabled_accessibility_services %s" % ":".join(service_names))
        self.shell("settings put secure accessibility_enabled 1")

    def enable_accessibility_service_db(self, service_name):
        """
        Enable an accessibility service
        :param service_name: the service to enable, in <package_name>/<service_name> format
        """
        subprocess.check_call(
            "adb shell \""
            "sqlite3 -batch /data/data/com.android.providers.settings/databases/settings.db \\\""
            "DELETE FROM secure WHERE name='enabled_accessibility_services' OR name='accessibility_enabled' "
            "OR name='touch_exploration_granted_accessibility_services' OR name='touch_exploration_enabled';"
            "INSERT INTO secure (name, value) VALUES "
            "('enabled_accessibility_services','" + service_name + "'), "
            "('accessibility_enabled','1'), "
            "('touch_exploration_granted_accessibility_services','" + service_name + "'), "
            "('touch_exploration_enabled','1')\\\";\"", shell=True)
        self.shell("stop")
        time.sleep(1)
        self.shell("start")

    def get_installed_apps(self):
        """
        Get the package names and apk paths of installed apps on the device
        :return: a dict, each key is a package name of an app and each value is the file path to the apk
        """
        app_lines = self.shell("pm list packages -f").splitlines()
        app_line_re = re.compile("package:(?P<apk_path>.+)=(?P<package>[^=]+)")
        package_to_path = {}
        for app_line in app_lines:
            m = app_line_re.match(app_line)
            if m:
                package_to_path[m.group('package')] = m.group('apk_path')
        return package_to_path

    def get_display_density(self):
        display_info = self.get_display_info()
        if 'density' in display_info:
            return display_info['density']
        else:
            return -1.0

    def __transform_point_by_orientation(self, xy, orientation_orig, orientation_dest):
        (x, y) = xy
        if orientation_orig != orientation_dest:
            if orientation_dest == 1:
                _x = x
                x = self.get_display_info()['width'] - y
                y = _x
            elif orientation_dest == 3:
                _x = x
                x = y
                y = self.get_display_info()['height'] - _x
        return x, y

    def get_orientation(self):
        display_info = self.get_display_info()
        if 'orientation' in display_info:
            return display_info['orientation']
        else:
            return -1

    def unlock(self):
        """
        Unlock the screen of the device
        """
        self.shell("input keyevent MENU")
        self.shell("input keyevent BACK")

    def press(self, key_code):
        """
        Press a key
        """
        self.shell("input keyevent %s" % key_code)

    def touch(self, x, y, orientation=-1, event_type=DOWN_AND_UP):
        if orientation == -1:
            orientation = self.get_orientation()
        self.shell("input tap %d %d" %
                   self.__transform_point_by_orientation((x, y), orientation, self.get_orientation()))

    def long_touch(self, x, y, duration=2000, orientation=-1):
        """
        Long touches at (x, y)
        """
        self.drag((x, y), (x, y), duration, orientation)

    def drag(self, start_xy, end_xy, duration, orientation=-1):
        """
        Sends drag event n PX (actually it's using C{input swipe} command.
        @param start_xy: starting point in pixel
        @param end_xy: ending point in pixel
        @param duration: duration of the event in ms
        @param orientation: the orientation (-1: undefined)
        """
        (x0, y0) = start_xy
        (x1, y1) = end_xy
        if orientation == -1:
            orientation = self.get_orientation()
        (x0, y0) = self.__transform_point_by_orientation((x0, y0), orientation, self.get_orientation())
        (x1, y1) = self.__transform_point_by_orientation((x1, y1), orientation, self.get_orientation())

        version = self.get_sdk_version()
        if version <= 15:
            self.logger.error("drag: API <= 15 not supported (version=%d)" % version)
        elif version <= 17:
            self.shell("input swipe %d %d %d %d" % (x0, y0, x1, y1))
        else:
            self.shell("input touchscreen swipe %d %d %d %d %d" % (x0, y0, x1, y1, duration))

    def type(self, text):
        if isinstance(text, str):
            escaped = text.replace("%s", "\\%s")
            encoded = escaped.replace(" ", "%s")
        else:
            encoded = str(text)
        # TODO find out which characters can be dangerous, and handle non-English characters
        self.shell("input text %s" % encoded)
