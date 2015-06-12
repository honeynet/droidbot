# This file is responsible for setup up the executing environment of droidbox app
# Here the executing environment includes:
# 1. Static environments: contacts, call logs, SMS, pre-installed apps, etc
#    2. Dynamic environments: continuous GPS, Accelerometer, etc
# The environment should be determined before app start running.
# We don't need to set up all environment aspects for one app,
# instead we select a subset according to static analysis result of app.
__author__ = 'liyc'

import logging

ENV_POLICIES = [
    "none",
    "dummy",
    "static",
    "file",
]


class AppEnv(object):
    """
    This class describes a environment attribute of device
    """
    # TODO implement this class and its subclasses
    pass


class StaticAppEnv(AppEnv):
    """
    This class describes a static environment attribute of device
    """
    pass


class DynamicAppEnv(AppEnv):
    """
    This class describes a static environment attribute of device
    """
    pass


class ContactAppEnv(StaticAppEnv):
    """
    This class describes a contact inside device
    """
    pass


class WifiStateAppEnv(StaticAppEnv):
    """
    This class describes the Wifi state of device
    """
    pass


class GPSAppEnv(DynamicAppEnv):
    """
    This class describes the continuous updating GPS data inside device
    """
    pass


class AppEnvManager(object):
    """
    AppEnvManager manages the environment of device in which an app will run.
    """

    def __init__(self, device, app, env_policy):
        """
        construct a new AppEnvManager instance
        :param device: instance of Device
        :param app: instance of App
        :param env_policy: policy of setting up environment, string
        :return:
        """
        self.logger = logging.getLogger('AppEnvManager')
        self.device = device
        self.app = app
        self.policy = env_policy
        self.envs = []

        if not self.policy or self == None:
            self.policy = "none"

        if self.policy == "none":
            self.env_factory = None
        elif self.policy == "dummy":
            self.env_factory = DummyEnvFactory()
        elif self.policy == "static":
            self.env_factory = StaticEnvFactory(app)
        else:
            self.env_factory = FileEnvFactory(self.policy)

    def add_env(self, env):
        """
        add a env to the envs list
        :param env: a env instance, should be subclass of AppEnv
        :return:
        """
        self.envs.append(env)

    def deploy(self):
        """
        deploy the environments to device (Emulator)
        :param device:
        :return:
        """
        self.logger.info("deploying environment, policy is %s" % self.policy)
        if self.env_factory != None:
            self.envs = self.env_factory.produce_envs()
        for env in self.envs:
            self.device.set_env(env)
        return

    def dump(self, file):
        """
        dump the environment information to a file
        :param file: the file path to output the environment
        :return:
        """
        # TODO implement this method

    def generateFromFactory(self, app_env_factory):
        """
        generate the environment of app from factory
        :param app_env_factory: the AppEnvFactory instance used to generate
        :return:
        """
        # TODO implement this method


class AppEnvFactory(object):
    """
    This class is responsible for produce a list of static and dynamic AppEnv
    """
    # TODO implement this class and its subclasses
    def produce_envs(self):
        return []


class DummyEnvFactory(AppEnvFactory):
    """
    A dummy factory which generate randomized app environment
    """
    pass


class StaticEnvFactory(AppEnvFactory):
    """
    A factory which generate ad hoc environment based on static analysis result of app
    """

    def __init__(self, app):
        """
        create a StaticEnvFactory from app analysis result
        :param instance of App
        """
        self.app = app


class FileEnvFactory(AppEnvFactory):
    """
    A factory which generate environment from file
    """

    def __init__(self, file):
        """
        create a FileEnvFactory from a json file
        :param file path string
        """
        self.file = file