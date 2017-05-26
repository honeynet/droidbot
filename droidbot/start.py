# helper file of droidbot
# it parses command arguments and send the options to droidbot
import argparse
import app_event
from droidbot import DroidBot


def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    parser = argparse.ArgumentParser(description="Start DroidBot to test an Android app.",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", action="store", dest="device_serial", required=True,
                        help="The serial number of target device (use `adb devices` to find)")
    parser.add_argument("-a", action="store", dest="apk_path", required=True,
                        help="The file path to target APK")
    parser.add_argument("-o", action="store", dest="output_dir",
                        help="directory of output")
    # parser.add_argument("-env", action="store", dest="env_policy",
    #                     help="policy to set up environment. Supported policies:\n"
    #                          "none\tno environment will be set. App will run in default environment of device; \n"
    #                          "dummy\tadd some fake contacts, SMS log, call log; \n"
    #                          "static\tset environment based on static analysis result; \n"
    #                          "<file>\tget environment policy from a json file.\n")
    parser.add_argument("-policy", action="store", dest="event_policy",
                        help='Policy to use for test input generation. Supported policies:\n'
                             # '%s\tno event will be sent, user should interact manually with device; \n'
                             # '%s\tuse "adb shell monkey" to send events; \n'
                             '\"%s\"\tGenerate random input events.\n'
                             # '%s\tsend events based on static analysis result; \n'
                             # '%s\tbased on dynamic app state, this policy requires framework instrumented\n'
                             '\"%s\"\tExplore the UI using a breadth-first strategy.\n'
                             '\"%s\"\tExplore the UI using a depth-first strategy.\n'
                             # '<%s>\tUse a script to customize input for certain states.\n'
                             # '%s\tmanually interact with your app, and we will record the events.\n'
                             %
                             (
                                 # app_event.POLICY_NONE,
                                 # app_event.POLICY_MONKEY,
                                 app_event.POLICY_RANDOM,
                                 # app_event.POLICY_STATIC,
                                 # app_event.POLICY_DYNAMIC,
                                 app_event.POLICY_BFS,
                                 app_event.POLICY_DFS,
                                 # app_event.POLICY_FILE,
                                 # app_event.POLICY_MANUAL
                             ))
    parser.add_argument("-no_shuffle", action="store_true", dest="no_shuffle",
                        help="Explore the UI without view shuffling")
    parser.add_argument("-script", action="store", dest="script_path",
                        help="Use a script to customize input for certain states.")
    parser.add_argument("-count", action="store", dest="event_count",
                        type=int, help="Number of events to generate in total")
    parser.add_argument("-interval", action="store", dest="event_interval",
                        type=int, help="Interval in seconds between each two events")
    parser.add_argument("-timeout", action="store", dest="timeout",
                        type=int, help="Timeout in seconds")
    parser.add_argument("-q", action="store_true", dest="quiet",
                        help="Run in quiet mode (dump warning messages only).")
    parser.add_argument("-use_hierarchy_viewer", action="store_true", dest="use_hierarchy_viewer",
                        help="Force use Hierarchy Viewer to dump UI states instead of UI Automator.")
    parser.add_argument("-use_method_profiling", action="store", dest="profiling_method",
                        help="Record method trace for each event. can be \"full\" or a sampling rate.")
    parser.add_argument("-use_with_droidbox", action="store_true", dest="with_droidbox",
                        help="Use DroidBot with DroidBox. Need to run on a DroidBox emulator.")
    options = parser.parse_args()
    # print options
    return options


def main():
    """
    the main function
    it starts a droidbot according to the arguments given in cmd line
    """
    opts = parse_args()
    import os
    if not os.path.exists(opts.apk_path):
        print "apk not exist"
        return

    droidbot = DroidBot(app_path=opts.apk_path,
                        device_serial=opts.device_serial,
                        output_dir=opts.output_dir,
                        # env_policy=opts.env_policy,
                        env_policy="none",
                        event_policy=opts.event_policy,
                        no_shuffle=opts.no_shuffle,
                        script_path=opts.script_path,
                        event_interval=opts.event_interval,
                        event_duration=opts.timeout,
                        event_count=opts.event_count,
                        quiet=opts.quiet,
                        with_droidbox=opts.with_droidbox,
                        use_hierarchy_viewer=opts.use_hierarchy_viewer,
                        profiling_method=opts.profiling_method)
    droidbot.start()
    return


if __name__ == "__main__":
    main()
