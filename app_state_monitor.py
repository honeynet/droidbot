# This file consists of the classes for monitoring states of app running on device
# App state can be:
#     1. UI state, i.e. the layout of current view
#     2. intent state, i.e. a list of intents the app can receive
__author__ = 'liyc'


class AppStateMonitor(object):
    """
    This class is responsible for monitoring the states of app
    Once there is a state change, notify the state listeners
    """

    def __init__(self, device_name, package_name = None):
        """
        initiate an AppStateMonitor
        :param device_name: the name of AVD
        :param package_name: the package name of app to monitor, if not given, monitor all apps
        :return:
        """
        self.device_name = device_name
        self.package_name = package_name
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
        # TODO implement this method