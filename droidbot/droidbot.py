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
from droidbox_script.droidbox import DroidBox

class DroidBot(object):
    """
    The main class of droidbot
    A robot which interact with Android automatically
    """
    # this is a single instance class
    instance = None

    def __init__(self, device_serial=None, package_name=None, app_path=None, output_dir=None,
                 env_policy=None, event_policy=None, with_droidbox=False,
                 event_count=None, event_interval=None, event_duration=None):
        """
        initiate droidbot with configurations
        :param options: the options which contain configurations of droidbot
        :return:
        """
        self.logger = logging.getLogger('DroidBot')
        DroidBot.instance = self

        self.output_dir = output_dir
        if output_dir is None:
            self.output_dir = "droidbot_out"
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)

        if device_serial is None:
            # Dirty Workaround: Set device_serial to Default='.*', because com/dtmilano/android/viewclient.py
            #  set serial to an arbitrary argument. IN connectToDeviceOrExit(..) line 2539f.
            device_serial = '.*'

        self.device = Device(device_serial)
        self.app = App(package_name, app_path)

        self.droidbox = None
        if with_droidbox:
            self.droidbox = DroidBox()

        self.env_manager = AppEnvManager(self.device, self.app, env_policy)
        self.event_manager = AppEventManager(self.device, self.app, event_policy,
                                             event_count, event_interval,
                                             event_duration)

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
        self.env_manager.deploy()

        if self.droidbox is not None:
            self.droidbox.set_apk(self.app.app_path)
            self.droidbox.start_unblocked()
            self.event_manager.start()
            self.droidbox.stop()
            self.droidbox.get_output()
        else:
            self.event_manager.start()

        self.device.disconnect()
