# This file is responsible for setup up the executing environment of droidbox app
# Here the executing environment includes:
# 1. Static environments: contacts, call logs, SMS, pre-installed apps, etc
#    2. Dynamic environments: continuous GPS, Accelerometer, etc
# The environment should be determined before app start running.
# We don't need to set up all environment aspects for one app,
# instead we select a subset according to static analysis result of app.
__author__ = 'liyc'

import logging
import json
import random
import time
import threading

from types import Device, App, Intent

ENV_POLICIES = [
    "none",
    "dummy",
    "static",
    "file",
]


class UnknownEnvException(Exception):
    pass


class AppEnv(object):
    """
    This class describes a environment attribute of device
    """
    def to_dict(self):
        return self.__dict__

    def to_json(self):
        json.dumps(self.to_dict())

    def __str__(self):
        return self.to_dict().__str__()

    def deploy(self, device):
        """
        deploy this env to device
        :param device: Device
        """
        raise NotImplementedError


class StaticAppEnv(AppEnv):
    """
    This class describes a static environment attribute of device
    """
    pass


class DynamicAppEnv(AppEnv):
    """
    This class describes a dynamic environment attribute of device
    usually we need to start a thread for this
    """
    pass


class ContactAppEnv(StaticAppEnv):
    """
    This class describes a contact inside device
    """
    def __init__(self, name='Lynn', phone="1234567890", email="droidbot@honeynet.com"):
        self.name = name
        self.phone = phone
        self.email = email
        self.env_type = 'contact'

    def deploy(self, device):
        """
        add a contact to the device
        """
        assert device.get_adb() is not None
        extra_string = self.__dict__
        extra_string.pop('env_type')
        contact_intent = Intent(prefix="start",
                                action="android.intent.action.INSERT",
                                mime_type="vnd.android.cursor.dir/contact",
                                extra_string=extra_string)
        device.send_intent(intent=contact_intent)
        time.sleep(2)
        device.get_adb().press("BACK")
        time.sleep(2)
        device.get_adb().press("BACK")


class SettingsAppEnv(StaticAppEnv):
    """
    This class describes settings of device
    """
    def __init__(self, table_name="system", name="screen_brightness", value="50"):
        self.table_name = table_name
        self.name = name
        self.value = value
        self.env_type = 'settings'

    def deploy(self, device):
        device.change_settings(self.table_name, self.name, self.value)


class CallLogEnv(StaticAppEnv):
    """
    call log
    """
    def __init__(self, phone="1234567890", call_in=True, accepted=True):
        """
        a call log
        :param phone: str, phone number of contact
        :param call_in: bool, True for call in, False for call out
        :param accepted: whether the call is accepted
        """
        self.phone = phone
        self.call_in = call_in
        self.accepted = accepted
        self.env_type = 'calllog'

    def deploy(self, device):
        if self.call_in:
            self.deploy_call_in(device)
        else:
            self.deploy_call_out(device)

    def deploy_call_in(self, device):
        """
        deploy call in log event to device
        """
        if not device.receive_call(self.phone):
            return
        time.sleep(1)
        if self.accepted:
            device.accept_call(self.phone)
            time.sleep(1)
        device.cancel_call(self.phone)

    def deploy_call_out(self, device):
        """
        deploy call out log event to device
        """
        device.call(self.phone)
        time.sleep(2)
        device.cancel_call(self.phone)


class SMSLogEnv(StaticAppEnv):
    """
    SMS log
    """
    def __init__(self, phone="1234567890", sms_in=True, content="Hello world"):
        """
        a call log
        :param phone: str, phone number of contact
        :param sms_in: bool, True for income message, False for outcome
        :param content: content of message
        """
        self.phone = phone
        self.sms_in = sms_in
        self.content = content
        self.env_type = 'smslog'

    def deploy(self, device):
        if self.sms_in:
            device.receive_sms(self.phone, self.content)
        else:
            device.send_sms(self.phone, self.content)


class GPSAppEnv(DynamicAppEnv):
    """
    This class describes the continuous updating GPS data inside device
    """
    def __init__(self, center_x=50, center_y=50, delta_x=1, delta_y=1):
        self.center_x = center_x
        self.center_y = center_y
        self.delta_x = delta_x
        self.delta_y = delta_y
        self.env_type = 'gps'

    def deploy(self, device):
        device.set_continuous_gps(self.center_x, self.center_y, self.delta_x, self.delta_y)


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
        self.logger.info("start deploying environment, policy is %s" % self.policy)
        if self.env_factory != None:
            self.envs = self.generateFromFactory(self.env_factory)
        if self.envs is None:
            return
        for env in self.envs:
            self.device.add_env(env)
        self.logger.info("finish deploying environment, policy is %s" % self.policy)

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
        return app_env_factory.produce_envs()


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
    def produce_envs(self):
        """
        produce a list of dummy environment
        """
        envs = []
        envs.append(ContactAppEnv())
        envs.append(SettingsAppEnv())
        envs.append(CallLogEnv())
        envs.append(SMSLogEnv())
        envs.append(GPSAppEnv())
        return envs


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

    def produce_envs(self):
        """
        generate app-specific envs
        """
        # TODO generate app-specific envs
        envs = []
        return envs


class FileEnvFactory(AppEnvFactory):
    """
    A factory which generate environment from file
    """

    def __init__(self, file):
        """
        create a FileEnvFactory from a json file
        :param file path string
        """
        envs = []
        self.file = file

    def produce_envs(self):
        """
        generate envs from file
        """
        # TODO generate envs from file
        envs = []
        return envs