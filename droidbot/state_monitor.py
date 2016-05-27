# This file consists of the classes for monitoring states of app running on device
# App state can be:
#     1. UI state, i.e. the layout of current view
#     2. intent state, i.e. a list of intents the app can receive
#     3. process state, i.e. pid-uid-package_name mapping
__author__ = 'liyc'


class StateMonitor(object):
    """
    This class is responsible for monitoring the states of device and app
    Once there is a state change, notify the state listeners
    """

    def __init__(self, device=None, app=None):
        """
        initiate a StateMonitor
        :param device: Device instance
        :param app: App instance
        :return:
        """
        self.enabled = True
        self.device = device
        self.app = app
        self.pid2user = {}
        self.pid2ppid = {}
        self.pid2name = {}
        self.listeners = set()

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

    def start(self):
        """
        start the monitor in a another thread.
        From now on, the on_state_updated method in listeners will be continuously called
        :return:
        """
        import threading
        self.enabled = True
        gps_thread = threading.Thread(
            target=self.maintain_process_mapping)
        gps_thread.start()
        return True

    def stop(self):
        self.enabled = False

    def maintain_process_mapping(self):
        """
        maintain pid2user mapping, pid2ppid mapping and pid2name mapping by continuously calling ps command
        """
        import time, subprocess
        while self.enabled:
            ps_out = subprocess.check_output(["adb", "shell", "ps", "-t"])
            # parse ps_out to update self.pid2uid mapping and self.pid2name mapping
            ps_out_lines = ps_out.splitlines()
            ps_out_head = ps_out_lines[0].split()
            if ps_out_head[0] != "USER" or ps_out_head[1] != "PID" or \
                ps_out_head[2] != "PPID" or ps_out_head[-1] != "NAME":
                self.device.logger.warning("ps command output format error: %s" % ps_out_head)
            for ps_out_line in ps_out_lines[1:]:
                segs = ps_out_line.split()
                if len(segs) < 4:
                    continue
                user = segs[0]
                pid = segs[1]
                ppid = segs[2]
                name = segs[-1]
                self.pid2name[pid] = name
                self.pid2ppid[pid] = ppid
                self.pid2user[pid] = user

            time.sleep(3)

    def get_ppids_by_pid(self, pid):
        """
        get the parent pids of given pid
        @return:
        """
        ppids = []
        while pid in self.pid2ppid:
            ppids.append(pid)
            pid = self.pid2ppid[pid]
        ppids.reverse()
        return ppids

    def get_names_by_pid(self, pid):
        """
        get name of the process and its parent processes
        @return:
        """
        ppids = self.get_ppids_by_pid(pid)
        names = []
        for ppid in ppids:
            names.append(self.pid2name[ppid])
        return names
