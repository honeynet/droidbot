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

    def __init__(self, device, app=None):
        """
        initiate an AppStateMonitor
        :param device: Device instance
        :param app: App instance
        :return:
        """
        self.device = device
        self.app = app
        self.pid2uid = {}
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
        gps_thread = threading.Thread(
            target=self.maintain_process_mapping)
        gps_thread.start()
        return True

    def maintain_process_mapping(self):
        """
        maintain a pid2uid mapping and pid2name mapping by continuously calling ps command
        """
        import time, subprocess
        while self.device.is_connected:
            ps_out = subprocess.check_output(["adb", "shell", "ps"])
            # TODO parse ps_out to update self.pid2uid mapping and self.pid2name mapping
            time.sleep(1)
