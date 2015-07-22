# Evaluate droidbot with droidbox
# basic idea is:
# A tool is better if more droidbox logs are generated when using the tool
import signal
from droidbot.app_env import AppEnvManager
from droidbot.app_event import AppEventManager
from droidbot.types import Device, App

__author__ = 'yuanchun'
import subprocess
import os
import re
import sys
import threading
import time


class DroidboxEvaluator(object):
    """
    evaluate test tool with droidbox
    make sure you have started droidbox emulator before evaluating
    """
    def __init__(self, droidbox_home, apk_path, duration, count, inteval):
        self.droidbox_home = droidbox_home
        self.apk_path = apk_path
        self.duration = duration
        self.count = count
        self.inteval = inteval
        self.droidbox = None
        self.log_count = 0
        self.log_counter_thread = None

    def start_evaluate(self):
        """
        start droidbox testing
        :return:
        """
        self.start_droidbox()
        self.count_log()
        # self.log_counter_thread = threading.Thread(target=self.log_counter_thread)
        # self.log_counter_thread.start()
        # while True:
        #     pass

    def start_droidbox(self):
        """
        start droidbox
        :return:
        """
        os.chdir(self.droidbox_home)
        self.droidbox = subprocess.Popen(
            ["sh", "droidbox.sh", self.apk_path, str(self.duration)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )

    def count_log(self):
        log_count_RE = re.compile('\s* Collected ([0-9]+) sandbox logs*')
        buf_size = 128
        while True:
            output = self.droidbox.stdout.read(buf_size)
            if output:
                print output
                m = log_count_RE.search(output)
                if not m:
                    continue
                log_count_str = m.group(1)
                self.log_count = int(log_count_str)
                print "log count: "
                print self.log_count

    def default_mode(self):
        """
        do nothing
        :return:
        """
        pass

    def droidbot_monkey(self):
        """
        try droidbot "monkey" mode
        :return:
        """
        device = Device()
        app = App(app_path=self.apk_path)

        env_manager = AppEnvManager(device, app, env_policy="none")
        event_manager = AppEventManager(
            device, app, "monkey", event_count=self.count, event_inteval=self.inteval)

        env_manager.deploy()
        event_manager.start()

        device.disconnect()

    def droidbot_static(self):
        """
        try droidbot "monkey" mode
        :return:
        """
        device = Device()
        app = App(app_path=self.apk_path)

        env_manager = AppEnvManager(device, app, env_policy="static")
        event_manager = AppEventManager(
            device, app, "static", event_count=self.count, event_inteval=self.inteval)

        env_manager.deploy()
        event_manager.start()

        device.disconnect()

    def droidbot_dynamic(self):
        """
        try droidbot "monkey" mode
        :return:
        """
        device = Device()
        app = App(app_path=self.apk_path)

        env_manager = AppEnvManager(device, app, env_policy="dummy")
        event_manager = AppEventManager(
            device, app, "dynamic", event_count=self.count, event_inteval=self.inteval)

        env_manager.deploy()
        event_manager.start()

        device.disconnect()


if __name__ == "__main__":
    apk_path = os.path.abspath(os.path.join("resources/TestDroidbot.apk"))
    print apk_path
    evaluator = DroidboxEvaluator(
        droidbox_home="/Users/yuanchun/tools/droidbox/DroidBox_4.1.1/",
        apk_path=apk_path,
        duration=100,
        count=1000,
        inteval=2
    )
    evaluator.start_evaluate()