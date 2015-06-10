# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
__author__ = 'liyc'
import sys
import argparse
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
    # usage = "python droidbot.py -p <package name> -n <number of event> " \
    #         "[-env <env policy>] [-event <event policy>] [-d <output directory>]\n" \
    #         "\t-p\tpackage name of target app\n" \
    #         "\t-n\tnumber of events to generate during testing\n" \
    #         "\t-env\tenvironment policy to use before app running\n" \
    #         "\t\tnone\tno environment will be set. App will run in default environment of device\n" \
    #         "\t\tdummy\tadd some fake contacts, SMS log, call log\n" \
    #         "\t\tstatic\tset environment based on static analysis result\n" \
    #         "\t\t<file>\tget environment policy from a json file\n" \
    #         "\t-event\tpolicy of sending events during app running\n" \
    #         "\t\tnone\tno event will be sent\n" \
    #         "\t\tmonkey\tpseudo-random events, same as \"adb shell monkey ...\"\n" \
    #         "\t\tstatic\tsend events based on static analysis result\n" \
    #         "\t\tdynamic\tsend events based on dynamic app state, this policy requires framework instrumented\n" \
    #         "\t\t<file>\tget event policy from a json file\n" \
    #         "\t-d\tdirectory to dump env and event json file\n" \
    #         "eg. python droidbot.py -p com.android.calendar -n 500 -env none -event monkey"
    parser = argparse.ArgumentParser(description="start a robot to interact with Android app",
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("-p", action="store", dest="package_name", nargs=1,
                        required=True, help="package name of target app")
    parser.add_argument("-n", action="store", dest="number", nargs=1,
                        required=True, type=int, help="number of events to generate during testing")
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
                        "<file>\tget event policy from a json file; \n")
    parser.add_argument("-d", action="store", dest="directory", nargs='?',
                        help="directory of output")
    parser.print_help()
    options = parser.parse_args()
    print options
    print vars(options)
    return options


def main(opts):
    """
    the main function
    it starts a HoneynetSocketServer according to
     the host and port given in opts
    :param opts: the options parsed by parse_args()
    """
    return


if __name__ == "__main__":
    opts = parse_args()
    main(opts)