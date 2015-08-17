# helper file of droidbot
# it parses command arguments and send the options to droidbot

__author__ = 'liyc'
import argparse
import logging
from argparse import RawTextHelpFormatter
from droidbot import DroidBot

def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    parser = argparse.ArgumentParser(description="start a robot to interact with Android app",
                                     formatter_class=RawTextHelpFormatter)
    parser.add_argument("-d", action="store", dest="device_serial",
                        help="serial number of target device")
    parser.add_argument("-p", action="store", dest="package_name",
                        help="package name of a pre-installed app, otherwise use -a option")
    parser.add_argument("-a", action="store", dest="app_path",
                        help="file path of target app, necessary for static analysis")
    parser.add_argument("-count", action="store", dest="event_count",
                        type=int, help="number of events to generate during testing")
    parser.add_argument("-interval", action="store", dest="event_interval",
                        type=int, help="interval between two events (seconds)")
    parser.add_argument("-duration", action="store", dest="event_duration",
                        type=int, help="duration of droidbot running (seconds)")
    parser.add_argument("-env", action="store", dest="env_policy",
                        help="policy to set up environment. Supported policies:\n"
                        "none\tno environment will be set. App will run in default environment of device; \n"
                        "dummy\tadd some fake contacts, SMS log, call log; \n"
                        "static\tset environment based on static analysis result; \n"
                        "<file>\tget environment policy from a json file.\n")
    parser.add_argument("-event", action="store", dest="event_policy",
                        help="policy to generate events. Supported policies:\n"
                        "monkey\tuse \"adb shell monkey\" to send events; \n" \
                        "random\tpseudo-random events, similar with monkey; \n" \
                        "static\tsend events based on static analysis result; \n" \
                        "dynamic\tsend events based on dynamic app state,"
                        " this policy requires framework instrumented; \n" \
                        "<file>\tget event policy from a json file.\n")
    parser.add_argument("-o", action="store", dest="output_dir",
                        help="directory of output")
    parser.add_argument("-droidbox", action="store_true", dest="with_droidbox",
                        help="start with droidbox")
    parser.add_argument("-q", action="store_true", dest="quiet",
                        help="run in quiet mode (dump warning messages only).")
    options = parser.parse_args()
    # print options
    return options


def main():
    """
    the main function
    it starts a droidbot according to the arguments given in cmd line
    """
    opts = parse_args()

    droidbot = DroidBot(device_serial=opts.device_serial,
                        package_name=opts.package_name,
                        app_path=opts.app_path,
                        output_dir=opts.output_dir,
                        env_policy=opts.env_policy,
                        event_policy=opts.event_policy,
                        with_droidbox=opts.with_droidbox,
                        event_interval=opts.event_interval,
                        event_duration=opts.event_duration,
                        event_count=opts.event_count,
                        quiet=opts.quiet)
    droidbot.start()
    return


if __name__ == "__main__":
    main()
