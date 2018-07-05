import threading
import logging
import time
import subprocess
from .adapter import Adapter


class ProcessMonitor(Adapter):
    """
    monitoring the state of process on the device
    """

    def __init__(self, device=None, app=None):
        """
        initiate a process monitor
        :param device: Device instance
        :param app: App instance
        :return:
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.enabled = True
        self.device = device
        self.app = app
        self.pid2user = {}
        self.pid2ppid = {}
        self.pid2name = {}
        self.listeners = set()
        self.lock = threading.Lock()

    def add_state_listener(self, state_listener):
        """
        add one state listener to the listeners list
        :param state_listener:
        :return:
        """
        self.listeners.add(state_listener)

    def remove_state_listener(self, state_listener):
        """
        add one listener from the listeners list
        :param state_listener: the listener to be removed
        :return:
        """
        self.listeners.remove(state_listener)

    def connect(self):
        """
        start the monitor in a another thread.
        From now on, the on_state_updated method in listeners will be continuously called
        :return:
        """
        self.enabled = True
        gps_thread = threading.Thread(target=self.maintain_process_mapping)
        gps_thread.start()
        return True

    def disconnect(self):
        self.enabled = False

    def check_connectivity(self):
        return self.enabled

    def maintain_process_mapping(self):
        """
        maintain pid2user mapping, pid2ppid mapping and pid2name mapping by continuously calling ps command
        """
        while self.enabled:
            if self.device is not None:
                ps_cmd = ["adb", "-s", self.device.serial, "shell", "ps"]
            else:
                ps_cmd = ["adb", "shell", "ps"]

            try:
                ps_out = subprocess.check_output(ps_cmd)
                if not isinstance(ps_out, str):
                    ps_out = ps_out.decode()
            except subprocess.CalledProcessError:
                continue

            # parse ps_out to update self.pid2uid mapping and self.pid2name mapping
            ps_out_lines = ps_out.splitlines()
            ps_out_head = ps_out_lines[0].split()
            if ps_out_head[0] != "USER" or ps_out_head[1] != "PID" \
                    or ps_out_head[2] != "PPID" or ps_out_head[-1] != "NAME":
                self.device.logger.warning("ps command output format error: %s" % ps_out_head)

            for ps_out_line in ps_out_lines[1:]:
                segs = ps_out_line.split()
                if len(segs) < 4:
                    continue
                user = segs[0]
                pid = segs[1]
                ppid = segs[2]
                name = segs[-1]
                self.lock.acquire()
                self.pid2name[pid] = name
                self.pid2ppid[pid] = ppid
                self.pid2user[pid] = user
                self.lock.release()

            time.sleep(1)
        print("[CONNECTION] %s is disconnected" % self.__class__.__name__)

    def get_ppids_by_pid(self, pid):
        """
        get the parent pids of given pid
        @return:
        """
        self.lock.acquire()
        ppids = []
        while pid in self.pid2ppid:
            ppids.append(pid)
            pid = self.pid2ppid[pid]
        self.lock.release()

        ppids.reverse()
        return ppids

    def get_names_by_pid(self, pid):
        """
        get name of the process and its parent processes
        @return:
        """
        ppids = self.get_ppids_by_pid(pid)
        names = []
        self.lock.acquire()
        for ppid in ppids:
            names.append(self.pid2name[ppid])
        self.lock.release()

        return names
