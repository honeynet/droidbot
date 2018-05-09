import logging
import socket
import subprocess
import time
from adapter import Adapter


class DroidBotConnException(Exception):
    """
    Exception in telnet connection
    """
    pass

class EOF(Exception):
    """
    Exception in telnet connection
    """
    pass

class DroidBotConn(Adapter):
    """
    a connection with DroidBot.
    """
    def __init__(self, device_unique_id,
                 app_path=None,
                 device_serial=None,
                 is_emulator=False,
                 output_dir=None,
                 env_policy=None,
                 policy_name=None,
                 random_input=False,
                 script_path=None,
                 event_count=None,
                 event_interval=None,
                 timeout=None,
                 keep_app=None,
                 keep_env=False,
                 cv_mode=False,
                 debug_mode=False,
                 profiling_method=None,
                 grant_perm=False,
                 enable_accessibility_hard=False,
                 master=None):
        """
        initiate a DroidBot connection
        :return:
        """
        self.device_unique_id = device_unique_id

        self.app_path = app_path
        self.device_serial = device_serial
        self.is_emulator = is_emulator
        self.output_dir = output_dir
        self.env_policy = env_policy
        self.policy_name = policy_name
        self.random_input = random_input
        self.script_path = script_path
        self.event_count = event_count
        self.event_interval = event_interval
        self.timeout = timeout
        self.keep_app = keep_app
        self.keep_env = keep_env
        self.cv_mode = cv_mode
        self.debug_mode = debug_mode
        self.profiling_method = profiling_method
        self.grant_perm = grant_perm
        self.enable_accessibility_hard = enable_accessibility_hard
        self.master = master

    def set_up(self):
        # start droidbot instance
        droidbot_cmd = ["droidbot",
                        "-d", self.device_serial,
                        "-a", self.app_path,
                        "-interval", str(self.event_interval),
                        "-count", str(self.event_count),
                        "-policy", "dfs_greedy",
                        "-grant_perm", "-keep_env", "-random",
                        "-o", "%s_%d" % \
                        (self.output_dir, self.device_unique_id),
                        "-use_method_profiling", self.profiling_method,
                        "-distributed", "worker"]
        if self.script_path is not None:
            droidbot_cmd += ["-script", self.script_path]
        if self.master is not None:
            droidbot_cmd += ["-master", self.master]
        if self.enable_accessibility_hard:
            droidbot_cmd += ["-accessibility_auto"]

        self.droidbot_p = subprocess.Popen(droidbot_cmd)
        self.pid = self.droidbot_p.pid

    def connect(self):
        self.connected = True

    def check_connectivity(self):
        """
        check if DroidBot is connected
        :return: True for connected
        """
        return self.connected

    def disconnect(self):
        """
        disconnect telnet
        """
        self.connected = False

    def tear_down(self):
        """
        stop DroidBot instance
        """
        self.droidbot_p.kill()

if __name__ == "__main__":
    pass
