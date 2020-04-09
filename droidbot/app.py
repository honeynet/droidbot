import logging
import os
import hashlib
from .intent import Intent


class App(object):
    """
    this class describes an app
    """

    def __init__(self, app_path, output_dir=None):
        """
        create an App instance
        :param app_path: local file path of app
        :return:
        """
        assert app_path is not None
        self.logger = logging.getLogger(self.__class__.__name__)

        self.app_path = app_path

        self.output_dir = output_dir
        if output_dir is not None:
            if not os.path.isdir(output_dir):
                os.makedirs(output_dir)

        from androguard.core.bytecodes.apk import APK
        self.apk = APK(self.app_path)
        self.package_name = self.apk.get_package()
        self.main_activity = self.apk.get_main_activity()
        self.permissions = self.apk.get_permissions()
        self.activities = self.apk.get_activities()
        self.possible_broadcasts = self.get_possible_broadcasts()
        self.dumpsys_main_activity = None
        self.hashes = self.get_hashes()

    def get_package_name(self):
        """
        get package name of current app
        :return:
        """
        return self.package_name

    def get_main_activity(self):
        """
        get package name of current app
        :return:
        """
        if self.main_activity is not None:
            return self.main_activity
        else:
            self.logger.warning("Cannot get main activity from manifest. Using dumpsys result instead.")
            return self.dumpsys_main_activity

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
        for receiver in self.apk.get_receivers():
            intent_filters = self.apk.get_intent_filters('receiver', receiver)
            actions = intent_filters['action'] if 'action' in intent_filters else []
            categories = intent_filters['category'] if 'category' in intent_filters else []
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
