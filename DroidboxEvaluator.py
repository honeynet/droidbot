# Evaluate droidbot with droidbox
# basic idea is:
# A tool is better if more droidbox logs are generated when using the tool
__author__ = 'yuanchun'
import subprocess
import os
import re
import logging
import sys
import threading
import time


class DroidboxEvaluator(object):
    """
    evaluate test tool with droidbox
    make sure you have started droidbox emulator before evaluating
    """
    MODE_DEFAULT = "default"
    MODE_MONKEY = "monkey"
    MODE_STATIC = "static"
    MODE_DYNAMIC = "dynamic"

    def __init__(self, droidbox_home, droidbot_home, apk_path, duration, count, interval):
        self.logger = logging.getLogger('DroidboxEvaluator')
        self.droidbox_home = os.path.abspath(droidbox_home)
        self.droidbot_home = os.path.abspath(droidbot_home)
        self.working_dir = os.path.abspath(os.path.curdir)
        self.apk_path = os.path.abspath(apk_path)
        self.duration = duration
        self.count = count
        self.interval = interval
        self.droidbox = None
        self.droidbot = None
        self.log_count = 0
        self.enable = False
        self.log_received = False
        self.default_mode_result = {}
        self.monkey_mode_result = {}
        self.static_mode_result = {}
        self.dynamic_mode_result = {}
        self.logger.info("Evaluator initialized")
        self.logger.info("droidbox_home:%s\ndroidbot_home:%s\napk_path:%s\n"
                         "duration:%d\ncount:%d\ninteval:%d\n" %
                         (self.droidbox_home, self.droidbot_home, self.apk_path,
                          self.duration, self.count, self.interval))

    def start_evaluate(self):
        """
        start droidbox testing
        :return:
        """
        self.evaluate_mode(DroidboxEvaluator.MODE_DEFAULT,
                           self.default_mode,
                           self.default_mode_result)
        # self.evaluate_mode(DroidboxEvaluator.MODE_MONKEY,
        #                    self.droidbot_monkey,
        #                    self.monkey_mode_result)
        # self.evaluate_mode(DroidboxEvaluator.MODE_STATIC,
        #                    self.droidbot_static,
        #                    self.static_mode_result)
        # self.evaluate_mode(DroidboxEvaluator.MODE_DYNAMIC,
        #                    self.droidbot_dynamic,
        #                    self.dynamic_mode_result)

    def evaluate_mode(self, mode, target, result):
        """
        evaluate a particular mode
        :param mode: str of mode
        :param target: the target function to run
        :param result: the result dict
        :return:
        """
        self.logger.info("evaluating [%s] mode" % mode)
        target()
        self.monitor_and_record(result)
        self.stop_droidbox()
        self.stop_droidbot()
        self.logger.info("finished evaluating [%s] mode" % mode)

    def start_droidbox(self):
        """
        start droidbox
        :return:
        """
        self.logger.info("starting droidbox")
        os.chdir(self.droidbox_home)
        self.droidbox = subprocess.Popen(
            ["sh", "droidbox.sh", self.apk_path, str(self.duration)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        threading.Thread(target=self.count_log).start()

    def wait_for_droidbox(self):
        # wait until first log generated
        while not self.log_received:
            time.sleep(1)
        self.logger.info("droidbox started")

    def stop_droidbox(self):
        if self.droidbox is None:
            return
        self.logger.info("stoping droidbox")
        self.droidbox.kill()
        time.sleep(2)
        self.enable = False
        time.sleep(1)
        self.droidbox = None

    def count_log(self):
        self.logger.info("start counting logs")
        log_count_re = re.compile('\s* Collected ([0-9]+) sandbox logs*')
        buf_size = 128
        self.log_count = 0
        self.enable = True
        self.log_received = False
        while self.enable:
            output = self.droidbox.stdout.read(buf_size)
            if output:
                self.logger.debug(output)
                self.log_received = True
                m = log_count_re.search(output)
                if not m:
                    continue
                log_count_str = m.group(1)
                self.log_count = int(log_count_str)
        self.logger.info("finish counting logs")

    def monitor_and_record(self, result):
        t = 0
        self.logger.info("start monitoring")
        try:
            while True:
                log_count = self.log_count
                result[t] = log_count
                time.sleep(self.interval)
                t += self.interval
                if t > self.duration:
                    return
        except KeyboardInterrupt as exception:
            self.logger.info(exception.message)
            self.stop_droidbox()
        self.logger.info("stop monitoring")
        self.logger.debug(result)

    def default_mode(self):
        """
        just start droidbox and do nothing
        :return:
        """
        self.start_droidbox()
        self.wait_for_droidbox()

    def start_droidbot(self, apk_path, count, interval,
                       env_policy, event_policy):
        """
        start droidbot with given arguments
        :param apk_path: path to target apk
        :param count: number of events
        :param interval: interval of each two events
        :param env_policy: policy to deploy environment
        :param event_policy: policy to send events
        :return:
        """
        self.logger.info("starting droidbot")
        os.chdir(self.droidbot_home)
        self.droidbot = subprocess.Popen(
            ["python", "start.py",
             "-a", apk_path,
             "-c", str(count),
             "-i", str(interval),
             "-env", env_policy,
             "-event", event_policy],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    def stop_droidbot(self):
        """
        stop droidbot
        :return:
        """
        if self.droidbot is None:
            return
        self.logger.info("stoping droidbot")
        self.droidbot.kill()
        time.sleep(2)
        self.droidbot = None

    def droidbot_monkey(self):
        """
        try droidbot "monkey" mode
        :return:
        """
        self.start_droidbox()
        self.wait_for_droidbox()
        self.start_droidbot(apk_path=self.apk_path,
                            count=self.log_count,
                            interval=self.interval,
                            env_policy="none",
                            event_policy="monkey")

    def droidbot_static(self):
        """
        try droidbot "static" mode
        :return:
        """
        self.start_droidbox()
        self.wait_for_droidbox()
        self.start_droidbot(apk_path=self.apk_path,
                            count=self.log_count,
                            interval=self.interval,
                            env_policy="static",
                            event_policy="static")

    def droidbot_dynamic(self):
        """
        try droidbot "dynamic" mode
        :return:
        """
        self.start_droidbox()
        self.wait_for_droidbox()
        self.start_droidbot(apk_path=self.apk_path,
                            count=self.log_count,
                            interval=self.interval,
                            env_policy="dummy",
                            event_policy="dynamic")

    def dump(self, out_file):
        out_file.write("time\t%s\t%s\t%s\t%s\n" %
                       (DroidboxEvaluator.MODE_DEFAULT,
                        DroidboxEvaluator.MODE_MONKEY,
                        DroidboxEvaluator.MODE_STATIC,
                        DroidboxEvaluator.MODE_DYNAMIC))
        t = 0
        while True:
            default_result = None
            monkey_result = None
            static_result = None
            dynamic_result = None
            if t in self.default_mode_result.keys():
                default_result = self.default_mode_result[t]
            if t in self.monkey_mode_result.keys():
                monkey_result = self.monkey_mode_result[t]
            if t in self.static_mode_result.keys():
                static_result = self.static_mode_result[t]
            if t in self.dynamic_mode_result.keys():
                dynamic_result = self.dynamic_mode_result[t]

            if default_result is None and monkey_result is None \
                    and static_result is None and dynamic_result is None:
                return

            out_file.write("%d\t%s\t%s\t%s\t%s\n" %
                           (t, default_result, monkey_result, static_result, dynamic_result))
            t += self.interval
            if t > self.duration:
                return


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    evaluator = DroidboxEvaluator(
        droidbox_home="/Users/yuanchun/tools/droidbox/DroidBox_4.1.1/",
        droidbot_home=".",
        apk_path="resources/TestDroidbot.apk",
        duration=10,
        count=1000,
        interval=2
    )
    try:
        evaluator.start_evaluate()
    except KeyboardInterrupt as e:
        print e.message
    evaluator.dump(sys.stdout)
