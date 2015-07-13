# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human

__author__ = 'liyc'
import logging
import sys
import os
from types import App, Device
from app_env import AppEnvManager
from app_event import AppEventManager
from connection import TelnetException, ADBException, MonkeyRunnerException


class DroidBot(object):
    """
    The main class of droidbot
    A robot which interact with Android automatically
    """
    # this is a single instance class
    instance = None

    def __init__(self, options):
        """
        initiate droidbot with configurations
        :param options: the options which contain configurations of droidbot
        :return:
        """
        self.logger = logging.getLogger('DroidBot')
        self.options = options
        if self.options.output_dir is None:
            self.options.output_dir = "droidbot_out"
        if not os.path.exists(self.options.output_dir):
            os.mkdir(self.options.output_dir)
        if self.options.device_serial is None:
            # Dirty Workaround: Set device_serial to Default='.*', because com/dtmilano/android/viewclient.py
            #  set serial to an arbitrary argument. IN connectToDeviceOrExit(..) line 2539f.
            self.options.device_serial = '.*'
        DroidBot.instance = self

    @staticmethod
    def get_instance():
        if DroidBot.instance is None:
            print "Error: DroidBot is not initiated!"
            sys.exit(-1)
        return DroidBot.instance

    def start(self):
        """
        start interacting
        :return:
        """
        device = Device(self.options.device_serial)
        app = App(self.options.package_name, self.options.app_path)

        env_manager = AppEnvManager(device, app, self.options.env_policy)
        event_manager = AppEventManager(device, app, self.options.event_policy, self.options.event_count)

        env_manager.deploy()
        event_manager.start()

        device.disconnect()
