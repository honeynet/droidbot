# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
from utils.connection import ADB

__author__ = 'liyc'
import sys
import argparse
import logging
from utils.types import App, Device
from app_env import AppEnvManager
from app_event import AppEventManager
from argparse import RawTextHelpFormatter
from app_env import AppEnvManager
from app_event import AppEventManager


class droidbot(object):
    """
    The main class of droidbot
    A robot which interact with Android automatically
    """

    def __init__(self, device, package_name, env_policy, event_policy):
        """
        initiate droidbot with configurations
        :param device: name of device droidbot is going to interact with
        :param package_name: package name of app droidbot is going to interact with
        :param env_policy: the policy used to set up device environment
        :param event_policy: the policy used to generate events at runtime
        :return:
        """
        self.device = device
        self.package_name = package_name
        self.env_policy = env_policy
        self.event_policy = event_policy

    def start(self):
        """
        start interacting
        :return:
        """
        # TODO implement this method
        pass


def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    parser = argparse.ArgumentParser(description="start a robot to interact with Android app",
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", action="store", dest="device_serial", nargs='?',
                        help="serial number of target device")
    parser.add_argument("-p", action="store", dest="package_name", nargs='?',
                        help="package name of a pre-installed app, otherwise use -a option")
    parser.add_argument("-a", action="store", dest="app_path", nargs='?',
                        help="file path of target app, necessary for static analysis")
    parser.add_argument("-c", action="store", dest="event_count", nargs='?',
                        type=int, help="number of events to generate during testing")
    parser.add_argument("-env", action="store", dest="env_policy", nargs='?',
                        help="policy to set up environment. Supported policies:\n"
                        "none\tno environment will be set. App will run in default environment of device; \n"
                        "dummy\tadd some fake contacts, SMS log, call log; \n"
                        "static\tset environment based on static analysis result; \n"
                        "<file>\tget environment policy from a json file.\n")
    parser.add_argument("-event", action="store", dest="event_policy", nargs='?',
                        help="policy to generate events. Supported policies:\n"
                        "none\tno event will be sent; \n" \
                        "monkey\tpseudo-random events, same as \"adb shell monkey ...\"; \n" \
                        "static\tsend events based on static analysis result; \n" \
                        "dynamic\tsend events based on dynamic app state,"
                        " this policy requires framework instrumented; \n" \
                        "<file>\tget event policy from a json file.\n")
    parser.add_argument("-o", action="store", dest="output_dir", nargs='?',
                        help="directory of output")
    options = parser.parse_args()
    return options


def main():
    """
    the main function
    it starts a droidbot according to the arguments given in cmd line
    """
    logging.basicConfig(level=logging.DEBUG)
    opts = parse_args()
    device = Device(opts.device_serial)
    device.get_adb()
    device.get_telnet()
    app = App(opts.package_name, opts.app_path)
    env_manager = AppEnvManager(device, app, opts.env_policy)
    event_manager = AppEventManager(device, app, opts.event_policy, opts.event_count)

    env_manager.deploy()
    event_manager.start()
    return


if __name__ == "__main__":
    main()