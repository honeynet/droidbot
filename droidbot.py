# This file contains the main class of droidbot
# It can be used after AVD was started, app was installed, and adb had been set up properly
# By configuring and creating a droidbot instance,
# droidbot will start interacting with Android in AVD like a human
__author__ = 'liyc'


class droidbot(object):
    """
    The main class of droidbot
    A robot which interact with Android automatically
    """

    def __init__(self, device, package_name, env_policy, event_policy):
        """
        initiate droidbot with configurations
        :param device: name of device droidbot is going to interact with
        :param package_name: package name of app droidbot is going to interact with
        :param env_policy: the policy used to set up device environment
        :param event_policy: the policy used to generate events at runtime
        :return:
        """
        self.device = device
        self.package_name = package_name
        self.env_policy = env_policy
        self.event_policy = event_policy

    def start(self):
        """
        start interacting
        :return:
        """
        # TODO implement this method
        pass