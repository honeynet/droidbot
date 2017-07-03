# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
import logging
import os
import sys

from device import Device
from app import App
from app_env import AppEnvManager
from app_event import AppEventManager
from input_manager import InputManager
from droidbox_scripts.droidbox import DroidBox


class DroidBot(object):
    """
    The main class of droidbot
    """
    # this is a single instance class
    instance = None

    def __init__(self,
                 app_path=None,
                 device_serial=None,
                 output_dir=None,
                 env_policy=None,
                 policy_name=None,
                 no_shuffle=False,
                 script_path=None,
                 event_count=None,
                 event_interval=None,
                 timeout=None,
                 keep_app=None,
                 dont_tear_down=False,
                 quiet=False,
                 with_droidbox=False,
                 use_hierarchy_viewer=False,
                 profiling_method=None,
                 grant_perm=False):
        """
        initiate droidbot with configurations
        :return:
        """
        logging.basicConfig(level=logging.WARNING if quiet else logging.INFO)

        self.logger = logging.getLogger('DroidBot')
        DroidBot.instance = self

        self.output_dir = output_dir
        if output_dir is not None:
            if not os.path.isdir(output_dir):
                os.mkdir(output_dir)

        self.dont_tear_down = dont_tear_down
        self.keep_app = keep_app

        # if device_serial is None:
        #     # Dirty Workaround: Set device_serial to Default='.*', because com/dtmilano/android/viewclient.py
        #     #  set serial to an arbitrary argument. IN connectToDeviceOrExit(..) line 2539f.
        #     # FIXED by requiring device_serial in cmd
        #     device_serial = '.*'

        self.device = None
        self.app = None
        self.droidbox = None
        self.env_manager = None
        self.input_manager = None

        self.enabled = True

        try:
            self.device = Device(device_serial=device_serial,
                                 output_dir=self.output_dir,
                                 use_hierarchy_viewer=use_hierarchy_viewer,
                                 grant_perm=grant_perm)
            self.app = App(app_path, output_dir=self.output_dir)

            if with_droidbox:
                self.droidbox = DroidBox(droidbot=self, output_dir=self.output_dir)

            self.env_manager = AppEnvManager(device=self.device,
                                             app=self.app,
                                             env_policy=env_policy)
            self.input_manager = InputManager(device=self.device,
                                              app=self.app,
                                              policy_name=policy_name,
                                              no_shuffle=no_shuffle,
                                              event_count=event_count,
                                              event_interval=event_interval,
                                              timeout=timeout,
                                              script_path=script_path,
                                              profiling_method=profiling_method)
        except Exception as e:
            self.logger.warning("Something went wrong: " + e.message)
            import traceback
            traceback.print_exc()
            self.stop()
            sys.exit(-1)

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
        if not self.enabled:
            return
        self.logger.info("Starting DroidBot")
        try:
            self.device.set_up()
            self.device.connect()

            self.device.install_app(self.app)
            self.env_manager.deploy()

            if self.droidbox is not None:
                self.droidbox.set_apk(self.app.app_path)
                self.droidbox.start_unblocked()
                self.input_manager.start()
                self.droidbox.stop()
                self.droidbox.get_output()
            else:
                self.input_manager.start()
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt.")
            pass
        except Exception as e:
            self.logger.warning("Something went wrong: " + e.message)
            import traceback
            traceback.print_exc()
            self.stop()
            sys.exit(-1)

        self.stop()
        self.logger.info("DroidBot Stopped")

    def stop(self):
        if self.env_manager is not None:
            self.env_manager.stop()
        if self.input_manager is not None:
            self.input_manager.stop()
        if self.droidbox is not None:
            self.droidbox.stop()
        self.device.disconnect()
        if not self.dont_tear_down:
            self.device.tear_down()
        if not self.keep_app:
            self.device.uninstall_app(self.app)
        self.enabled = False


class DroidBotException(Exception):
    pass
