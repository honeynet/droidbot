import logging
import os
import subprocess
import hashlib
from intent import Intent


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
        self.permissions = self.androguard.a.get_permissions()

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
            subprocess.check_call(["adb", "-s", device.serial, "pull", app_path_in_device, app_path])
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

    def get_permissions(self):
        """
        get package name of current app
        :return:
        """
        if self.permissions is None:
            self.permissions = self.get_androguard_analysis().a.get_permissions()
        return self.permissions

    def get_start_intent(self):
        """
        get an intent to start the app
        :return: Intent
        """
        package_name = self.get_package_name()
        if self.get_main_activity():
            package_name += "/%s" % self.get_main_activity()
        return Intent(suffix=package_name)

    def get_start_with_profiling_intent(self, trace_file, sampling=None):
        """
        get an intent to start the app with profiling
        :return: Intent
        """
        package_name = self.get_package_name()
        if self.get_main_activity():
            package_name += "/%s" % self.get_main_activity()
        if sampling is not None:
            return Intent(prefix="start --start-profiler %s --sampling %d" % (trace_file, sampling), suffix=package_name)
        else:
            return Intent(prefix="start --start-profiler %s" % trace_file, suffix=package_name)

    def get_stop_intent(self):
        """
        get an intent to stop the app
        :return: Intent
        """
        package_name = self.get_package_name()
        return Intent(prefix="force-stop", suffix=package_name)

    def get_possible_broadcasts(self):
        possible_broadcasts = set()

        androguard_a = self.get_androguard_analysis().a
        receivers = androguard_a.get_receivers()

        for receiver in receivers:
            intent_filters = androguard_a.get_intent_filters('receiver', receiver)
            if 'action' in intent_filters:
                actions = intent_filters['action']
            else:
                actions = []
            if 'category' in intent_filters:
                categories = intent_filters['category']
            else:
                categories = []
            categories.append(None)
            for action in actions:
                for category in categories:
                    intent = Intent(prefix='broadcast', action=action, category=category)
                    possible_broadcasts.add(intent)
        return possible_broadcasts

    def get_hashes(self, block_size=2 ** 8):
        """
        Calculate MD5,SHA-1, SHA-256
        hashes of APK input file
        @param block_size:
        """
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        f = open(self.app_path, 'rb')
        while True:
            data = f.read(block_size)
            if not data:
                break

            md5.update(data)
            sha1.update(data)
            sha256.update(data)
        return [md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()]


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
        self.d = None
        self.dx = None

    def get_detailed_analysis(self):
        from androguard.misc import AnalyzeDex
        self.d, self.dx = AnalyzeDex(self.a.get_dex(), raw=True)
