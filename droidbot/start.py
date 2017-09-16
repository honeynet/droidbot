# helper file of droidbot
# it parses command arguments and send the options to droidbot
import argparse
import input_manager
import input_policy
import env_manager
from droidbot import DroidBot


def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    parser = argparse.ArgumentParser(description="Start DroidBot to test an Android app.",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-d", action="store", dest="device_serial", required=False,
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
    parser.add_argument("-policy", action="store", dest="input_policy", default=input_manager.DEFAULT_POLICY,
                        help='Policy to use for test input generation. '
                             'Default: %s.\nSupported policies:\n' % input_manager.DEFAULT_POLICY +
                             '  \"%s\" -- No event will be sent, user should interact manually with device; \n'
                             '  \"%s\" -- Use "adb shell monkey" to send events; \n'
                             '  \"%s\" -- Explore UI using a naive depth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a greedy depth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a naive breadth-first strategy;\n'
                             '  \"%s\" -- Explore UI using a greedy breadth-first strategy;\n'
                             %
                             (
                                 input_policy.POLICY_NONE,
                                 input_policy.POLICY_MONKEY,
                                 input_policy.POLICY_NAIVE_DFS,
                                 input_policy.POLICY_GREEDY_DFS,
                                 input_policy.POLICY_NAIVE_BFS,
                                 input_policy.POLICY_GREEDY_DFS,
                             ))
    parser.add_argument("-script", action="store", dest="script_path",
                        help="Use a script to customize input for certain states.")
    parser.add_argument("-count", action="store", dest="count", default=input_manager.DEFAULT_EVENT_COUNT,
                        type=int, help="Number of events to generate in total. "
                                       "Default: %d" % input_manager.DEFAULT_EVENT_COUNT)
    parser.add_argument("-interval", action="store", dest="interval", default=input_manager.DEFAULT_EVENT_INTERVAL,
                        type=int, help="Interval in seconds between each two events. "
                                       "Default: %d" % input_manager.DEFAULT_EVENT_INTERVAL)
    parser.add_argument("-timeout", action="store", dest="timeout", default=input_manager.DEFAULT_TIMEOUT,
                        type=int, help="Timeout in seconds, -1 means unlimited. "
                                       "Default: %d" % input_manager.DEFAULT_TIMEOUT)
    parser.add_argument("-cv", action="store_true", dest="cv_mode",
                        help="Use OpenCV (instead of UIAutomator) to identify UI components. "
                             "CV mode requires opencv-python installed.")
    parser.add_argument("-debug", action="store_true", dest="debug_mode",
                        help="Run in debug mode (dump debug messages).")
    parser.add_argument("-random", action="store_true", dest="random_input",
                        help="Add randomness to input events.")
    parser.add_argument("-keep_app", action="store_true", dest="keep_app",
                        help="Keep the app on the device after testing.")
    parser.add_argument("-keep_env", action="store_true", dest="keep_env",
                        help="Keep the test environment (eg. minicap and accessibility service) after testing.")
    parser.add_argument("-use_method_profiling", action="store", dest="profiling_method",
                        help="Record method trace for each event. can be \"full\" or a sampling rate.")
    parser.add_argument("-grant_perm", action="store_true", dest="grant_perm",
                        help="Grant all permissions while installing. Useful for Android 6.0+.")
    parser.add_argument("-is_emulator", action="store_true", dest="is_emulator",
                        help="Declare the target device to be an emulator, which would be treated specially by DroidBot.")
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
        print "APK does not exist."
        return
    if not opts.output_dir and opts.cv_mode:
        print "To run in CV mode, you need to specify an output dir (using -o option)."

    droidbot = DroidBot(app_path=opts.apk_path,
                        device_serial=opts.device_serial,
                        is_emulator=opts.is_emulator,
                        output_dir=opts.output_dir,
                        # env_policy=opts.env_policy,
                        env_policy=env_manager.POLICY_NONE,
                        policy_name=opts.input_policy,
                        random_input=opts.random_input,
                        script_path=opts.script_path,
                        event_interval=opts.interval,
                        timeout=opts.timeout,
                        event_count=opts.count,
                        cv_mode=opts.cv_mode,
                        debug_mode=opts.debug_mode,
                        keep_app=opts.keep_app,
                        keep_env=opts.keep_env,
                        profiling_method=opts.profiling_method,
                        grant_perm=opts.grant_perm)
    droidbot.start()
    return


if __name__ == "__main__":
    main()
