# Evaluate DroidBot with androcov
# basic idea is:
# A tool is better if it has higher coverage
import argparse
import os
import logging
import sys
import threading
import time
import subprocess
from datetime import datetime
from droidbot.droidbot import DroidBot


START_EMULATOR_CMD = "emulator -avd %s -port %d -wipe-data"
AVD_PORT = 5564


class CoverageEvaluator(object):
    """
    evaluate test tool with DroidBox
    make sure you have started droidbox emulator before evaluating
    """
    MODE_DEFAULT = "1.default"
    MODE_MONKEY = "2.monkey"
    MODE_RANDOM = "3.random"
    MODE_STATIC = "4.static"
    MODE_DYNAMIC = "5.dynamic"

    def __init__(self, start_emu_cmd, device_serial, apk_path,
                 event_duration, event_count, event_interval,
                 output_dir, androcov_path, android_jar_path):
        self.modes = {
            CoverageEvaluator.MODE_DEFAULT: self.default_mode,
            CoverageEvaluator.MODE_MONKEY: self.adb_monkey,
            # CoverageEvaluator.MODE_RANDOM: self.droidbot_random,
            # CoverageEvaluator.MODE_STATIC: self.droidbot_static,
            CoverageEvaluator.MODE_DYNAMIC: self.droidbot_dynamic
        }

        self.logger = logging.getLogger(self.__class__.__name__)
        self.start_emu_cmd = start_emu_cmd
        self.device_serial = device_serial
        self.apk_path = os.path.abspath(apk_path)
        self.output_dir = output_dir
        self.androcov_path = androcov_path
        self.android_jar_path = android_jar_path

        if self.output_dir is None:
            self.output_dir = "evaluation_reports/"
        self.output_dir = os.path.abspath(self.output_dir)
        if not os.path.exists(self.output_dir):
            os.mkdir(self.output_dir)
        self.temp_dir = os.path.join(self.output_dir, "temp")
        if os.path.exists(self.temp_dir):
            import shutil
            shutil.rmtree(self.temp_dir)
        os.mkdir(self.temp_dir)
        self.androcov_output_dir = os.path.join(self.temp_dir, "androcov_out")
        os.mkdir(self.androcov_output_dir)

        self.output_dirs = {}
        for mode in self.modes:
            self.output_dirs[mode] = os.path.join(self.output_dir, mode)

        self.androcov = self.androcov_instrument()
        self.apk_path = self.androcov.apk_path

        now = datetime.now()
        self.report_title = now.strftime("Evaluation_Report_%Y-%m-%d_%H%M")
        result_file_name = self.report_title + ".md"
        self.result_file_path = os.path.join(self.output_dir, result_file_name)

        self.event_duration = event_duration
        if self.event_duration is None:
            self.event_duration = 200
        self.event_count = event_count
        if self.event_count is None:
            self.event_count = 200
        self.event_interval = event_interval
        if self.event_interval is None:
            self.event_interval = 2

        self.record_interval = self.event_duration / 20
        if self.record_interval < 2:
            self.record_interval = 2

        self.emulator = None
        self.droidbot = None

        self.result = {}

        self.logger.info("Evaluator initialized")
        self.logger.info("apk_path:%s\n"
                         "duration:%d\ncount:%d\ninteval:%d\nreport title:%s" %
                         (self.apk_path, self.event_duration,
                          self.event_count, self.event_interval, self.report_title))

        self.enabled = True

    def start_evaluate(self):
        """
        start droidbox testing
        :return:
        """
        if not self.enabled:
            return

        for mode in self.modes:
            self.evaluate_mode(mode, self.modes[mode])
        self.dump_result(sys.stdout)
        result_file = open(self.result_file_path, "w")
        self.dump_result(result_file)
        result_file.close()

    def androcov_instrument(self):
        """
        instrument the app with androcov
        @return:
        """
        subprocess.check_call(["java", "-jar", self.androcov_path,
                               "-i", self.apk_path, "-o", self.androcov_output_dir,
                               "-sdk", self.android_jar_path])
        import androcov_report
        return androcov_report.Androcov(androcov_dir=self.androcov_output_dir)

    def evaluate_mode(self, mode, target):
        """
        evaluate a particular mode
        :param mode: str of mode
        :param target: the target function to run
        :return:
        """
        if not self.enabled:
            return
        self.logger.info("evaluating [%s] mode" % mode)
        self.start_emulator()
        target_thread = threading.Thread(target=target)
        target_thread.start()
        self.monitor_and_record(mode)
        self.stop_modules()
        self.stop_emulator()
        self.logger.info("finished evaluating [%s] mode" % mode)

    def start_emulator(self):
        self.emulator = subprocess.Popen(self.start_emu_cmd.split(),
                                         stdin=subprocess.PIPE,
                                         stdout=subprocess.PIPE)
        self.wait_for_device()

    def stop_modules(self):
        if self.droidbot is not None:
            self.droidbot.stop()
            time.sleep(5)

    def stop_emulator(self):
        if not self.emulator:
            return
        self.emulator.terminate()
        time.sleep(5)

    def wait_for_device(self):
        """
        wait until the device is fully booted
        :return:
        """
        try:
            subprocess.check_call(["adb", "-s", self.device_serial, "wait-for-device"])
            while True:
                out = subprocess.check_output(["adb", "-s", self.device_serial, "shell",
                                               "getprop", "init.svc.bootanim"]).split()[0]
                if out == "stopped":
                    break
                time.sleep(3)
        except:
            self.logger.warning("error waiting for device")

    def monitor_and_record(self, mode):
        if not self.enabled:
            return
        self.result[mode] = {}
        self.logger.info("start monitoring")
        try:
            time.sleep(self.event_duration)
        except KeyboardInterrupt:
            self.stop()
        mode_logcat_path = os.path.join(self.output_dirs[mode], "logcat.log")
        self.result[mode] = self.androcov.gen_androcov_report(mode_logcat_path)
        self.logger.info("stop monitoring")
        self.logger.debug(self.result)

    def stop(self):
        self.enabled = False

    def start_droidbot(self, env_policy, event_policy, output_dir):
        """
        start droidbot with given arguments
        :param env_policy: policy to deploy environment
        :param event_policy: policy to send events
        :param output_dir: droidbot output directory
        :return:
        """
        if not self.enabled:
            return
        self.logger.info("starting droidbot")
        self.droidbot = DroidBot(device_serial=self.device_serial,
                                 app_path=self.apk_path,
                                 env_policy=env_policy,
                                 event_policy=event_policy,
                                 event_count=self.event_count,
                                 event_duration=self.event_duration,
                                 event_interval=self.event_interval,
                                 output_dir=output_dir,
                                 quiet=True)
        self.droidbot.start()

    def default_mode(self):
        self.start_droidbot(env_policy="none",
                            event_policy="none",
                            output_dir=self.output_dirs[CoverageEvaluator.MODE_DEFAULT])

    def adb_monkey(self):
        """
        try droidbot "monkey" mode
        :return:
        """
        self.start_droidbot(env_policy="none",
                            event_policy="monkey",
                            output_dir=self.output_dirs[CoverageEvaluator.MODE_MONKEY])

    def droidbot_random(self):
        """
        try droidbot "random" mode
        :return:
        """
        self.start_droidbot(env_policy="none",
                            event_policy="random",
                            output_dir=self.output_dirs[CoverageEvaluator.MODE_RANDOM])

    def droidbot_static(self):
        """
        try droidbot "static" mode
        :return:
        """
        self.start_droidbot(env_policy="none",
                            event_policy="static",
                            output_dir=self.output_dirs[CoverageEvaluator.MODE_STATIC])

    def droidbot_dynamic(self):
        """
        try droidbot "dynamic" mode
        :return:
        """
        self.start_droidbot(env_policy="none",
                            event_policy="dynamic",
                            output_dir=self.output_dirs[CoverageEvaluator.MODE_DYNAMIC])

    def result_safe_get(self, mode_tag=None, item_key=None, timestamp=None):
        """
        get an item from result
        """
        if mode_tag is None:
            return self.result
        if mode_tag in self.result:
            result_mode = self.result[mode_tag]
            if item_key is None:
                return result_mode
            if isinstance(result_mode, dict) and item_key in result_mode:
                result_item = result_mode[item_key]
                if timestamp is None:
                    return result_item
                if isinstance(result_item, dict) and timestamp in result_item:
                    return result_item[timestamp]
        return None

    def dump_result(self, out_file):
        modes = self.result_safe_get()
        if modes is None or not modes:
            return
        else:
            modes = list(modes.keys())
            modes.sort()

        out_file.write("# %s\n\n" % self.report_title)

        out_file.write("## About\n\n")
        out_file.write("This report is generated automatically by %s "
                       "with options:\n\n"
                       "+ apk_path=%s\n"
                       "+ event_duration=%s\n"
                       "+ event_interval=%s\n"
                       "+ event_count=%s\n\n"
                       % (self.__class__.__name__, os.path.basename(self.apk_path),
                          self.event_duration, self.event_interval, self.event_count))

        out_file.write("## Apk Info\n\n")
        out_file.write("|Item|Value|\n")
        out_file.write("|----|----|\n")
        out_file.write("|Package Name|%s|\n" % self.droidbot.app.get_package_name())
        out_file.write("|Main Activity|%s|\n" % self.droidbot.app.get_main_activity())
        apk_hashes = self.droidbot.app.get_hashes()
        out_file.write("|Hash (md5)|%s|\n" % apk_hashes[0])
        out_file.write("|Hash (sha1)|%s|\n" % apk_hashes[1])
        out_file.write("|Hash (sha256)|%s|\n\n" % apk_hashes[2])

        out_file.write("### Permissions\n\n")
        permissions = self.droidbot.app.get_androguard_analysis().a.get_permissions()
        for permission in permissions:
            out_file.write("+ %s\n" % permission)

        out_file.write("\n## Data\n\n")
        out_file.write("### Summary\n\n")
        # gen head lines
        th1 = "|\titem\t|"
        th2 = "|----|"
        for mode in modes:
            th1 += "\t%s\t|" % mode
            th2 += "----|"
        th1 += "\n"
        th2 += "\n"
        out_file.write(th1)
        out_file.write(th2)

        # gen content
        item_keys = self.result_safe_get(modes[0])
        if item_keys is None:
            item_keys = []
        else:
            item_keys = item_keys.keys()

        for item_key in item_keys:
            item_sample_value = self.result_safe_get(modes[0], item_key)
            if item_sample_value is None:
                continue
            if not isinstance(item_sample_value, str)\
                    and not isinstance(item_sample_value, int)\
                    and not isinstance(item_sample_value, float):
                continue

            tl = "|\t%s\t|" % item_key
            for mode in modes:
                item_value = self.result_safe_get(mode, item_key)
                tl += "\t%s\t|" % item_value
            tl += "\n"
            out_file.write(tl)

        out_file.write("\n### Tendency\n\n")
        # gen head lines
        th1 = "|\ttime\t|"
        th2 = "|----|"
        for mode in modes:
            th1 += "\t%s\t|" % mode
            th2 += "----|"
        th1 += "\n"
        th2 += "\n"
        out_file.write(th1)
        out_file.write(th2)

        # gen content
        timestamps = []
        for mode in modes:
            mode_timestamps = self.result_safe_get(mode, "timestamp_count")
            if not isinstance(mode_timestamps, dict):
                continue
            timestamps.extend(mode_timestamps)
        timestamps = sorted(set(timestamps))

        reached_method_count_in_last_timestamp = {}
        for mode in modes:
            reached_method_count_in_last_timestamp[mode] = 0
        for timestamp in timestamps:
            tl = "|\t%d\t|" % timestamp
            for mode in modes:
                # all_methods_count = self.result_safe_get(mode, "all_methods_count")
                reached_method_count = self.result_safe_get(mode, "timestamp_count", timestamp)
                if isinstance(reached_method_count, int):
                    reached_method_count_in_last_timestamp[mode] = reached_method_count
                else:
                    reached_method_count = reached_method_count_in_last_timestamp[mode]
                tl += "\t%s\t|" % reached_method_count
            tl += "\n"
            out_file.write(tl)
        out_file.flush()


def parse_args():
    """
    parse command line input
    generate options including host name, port number
    """
    description = "Run different testing bots on droidbox, and compare their log counts."
    parser = argparse.ArgumentParser(description=description,
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-avd", action="store", dest="avd_name", required=True,
                        help="avd name of target emulator")
    parser.add_argument("-a", action="store", dest="apk_path", required=True,
                        help="file path of target app, necessary for static analysis")
    parser.add_argument("-count", action="store", dest="event_count",
                        type=int, help="number of events to generate during testing")
    parser.add_argument("-interval", action="store", dest="event_interval",
                        type=int, help="interval between two events (seconds)")
    parser.add_argument("-duration", action="store", dest="event_duration",
                        type=int, help="duration of droidbot running (seconds)")
    parser.add_argument("-o", action="store", dest="output_dir",
                        help="directory of output")
    parser.add_argument("-androcov", action="store", dest="androcov_path", required=True,
                        help="path to androcov.jar")
    parser.add_argument("-sdk", action="store", dest="android_jar_path", required=True,
                        help="path to Sdk/platforms/android-XX/android.jar")
    options = parser.parse_args()
    # print options
    return options


if __name__ == "__main__":
    opts = parse_args()
    logging.basicConfig(level=logging.INFO)
    device_serial = "emulator-%d" % AVD_PORT
    start_emu_cmd = START_EMULATOR_CMD % (opts.avd_name, AVD_PORT)
    evaluator = CoverageEvaluator(
        start_emu_cmd=start_emu_cmd,
        device_serial=device_serial,
        apk_path=opts.apk_path,
        event_duration=opts.event_duration,
        event_count=opts.event_count,
        event_interval=opts.event_interval,
        output_dir=opts.output_dir,
        androcov_path=opts.androcov_path,
        android_jar_path=opts.android_jar_path
    )
    try:
        evaluator.start_evaluate()
    except KeyboardInterrupt:
        evaluator.stop()
        evaluator.dump_result(sys.stdout)
