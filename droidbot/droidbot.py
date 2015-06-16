# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human

__author__ = 'liyc'
import logging
from types import App, Device
from app_env import AppEnvManager
from app_event import AppEventManager
from connection import TelnetException, ADBException, MonkeyRunnerException


class DroidBot(object):
    """
    The main class of droidbot
    A robot which interact with Android automatically
    """

    def __init__(self, options):
        """
        initiate droidbot with configurations
        :param options: the options which contain configurations of droidbot
        :return:
        """
        self.logger = logging.getLogger('DroidBot')
        self.options = options

    def start(self):
        """
        start interacting
        :return:
        """
        try:
            device = Device(self.options.device_serial)
            app = App(self.options.package_name, self.options.app_path)
        except TelnetException as te:
            # allow telnet not connected
            self.logger.exception(te)

        env_manager = AppEnvManager(device, app, self.options.env_policy)
        event_manager = AppEventManager(device, app, self.options.event_policy, self.options.event_count)

        env_manager.deploy()
        event_manager.start()
