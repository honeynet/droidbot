# This file is responsible for setup up the executing environment of droidbox app
# Here the executing environment includes:
# 1. Static environments: contacts, call logs, SMS, pre-installed apps, etc
# 2. Dynamic environments: continuous GPS, Accelerometer, etc
# The environment should be determined before app start running.
# We don't need to set up all environments for one app,
# instead we select a subset according to static analysis result of app.
import logging
import json
import time
import os

POLICY_NONE = "none"
POLICY_DUMMY = "dummy"
POLICY_STATIC = "static"

DEFAULT_POLICY = POLICY_NONE


class UnknownEnvException(Exception):
    pass


class AppEnv(object):
    """
    This class describes a environment attribute of device
    """

    def to_dict(self):
        return self.__dict__

    def to_json(self):
        return json.dumps(self.to_dict())

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

    def deploy(self, device):
        raise NotImplementedError


class DynamicAppEnv(AppEnv):
    """
    This class describes a dynamic environment attribute of device
    usually we need to start a thread for this
    """

    def deploy(self, device):
        raise NotImplementedError


class ContactAppEnv(StaticAppEnv):
    """
    This class describes a contact inside device
    """

    def __init__(self, name='Lynn', phone="1234567890", email="droidbot@honeynet.com", env_dict=None):
        if env_dict is not None:
            self.__dict__ = env_dict
            return
        self.name = name
        self.phone = phone
        self.email = email
        self.env_type = 'contact'

    def deploy(self, device):
        """
        add a contact to the device
        """
        contact_data = self.__dict__
        contact_data.pop('env_type')
        return device.add_contact(contact_data)


class SettingsAppEnv(StaticAppEnv):
    """
    This class describes settings of device
    """

    def __init__(self, table_name="system", name="screen_brightness", value="50", env_dict=None):
        if env_dict is not None:
            self.__dict__ = env_dict
            return
        self.table_name = table_name
        self.name = name
        self.value = value
        self.env_type = 'settings'

    def deploy(self, device):
        return device.change_settings(self.table_name, self.name, self.value)


class CallLogEnv(StaticAppEnv):
    """
    call log
    """

    def __init__(self, phone="1234567890", call_in=True, accepted=True, env_dict=None):
        """
        a call log
        :param phone: str, phone number of contact
        :param call_in: bool, True for call in, False for call out
        :param accepted: whether the call is accepted
        """
        if env_dict is not None:
            self.__dict__ = env_dict
            return
        self.phone = phone
        self.call_in = call_in
        self.accepted = accepted
        self.env_type = 'calllog'

    def deploy(self, device):
        if self.call_in:
            return self.deploy_call_in(device)
        else:
            return self.deploy_call_out(device)

    def deploy_call_in(self, device):
        """
        deploy call in log event to device
        """
        if not device.receive_call(self.phone):
            return False
        time.sleep(1)
        if self.accepted:
            device.accept_call(self.phone)
            time.sleep(1)
        return device.cancel_call(self.phone)

    def deploy_call_out(self, device):
        """
        deploy call out log event to device
        """
        device.call(self.phone)
        time.sleep(2)
        return device.cancel_call(self.phone)


class DummyFilesEnv(StaticAppEnv):
    """
    push dummy files to device
    """

    def __init__(self, dummy_files_dir=None):
        """
        :param: dummy_files_dir: directory to dummy files
        """
        if dummy_files_dir is None:
            import pkg_resources
            dummy_files_dir = pkg_resources.resource_filename("droidbot", "resources/dummy_documents")

        self.dummy_files_dir = dummy_files_dir
        self.env_type = "dummy_files"

    def deploy(self, device):
        device.push_file(self.dummy_files_dir)


class SMSLogEnv(StaticAppEnv):
    """
    SMS log
    """

    def __init__(self, phone="1234567890", sms_in=True, content="Hello world", env_dict=None):
        """
        a call log
        :param phone: str, phone number of contact
        :param sms_in: bool, True for income message, False for outcome
        :param content: content of message
        """
        if env_dict is not None:
            self.__dict__ = env_dict
            return

        self.phone = phone
        self.sms_in = sms_in
        self.content = content
        self.env_type = 'smslog'

    def deploy(self, device):
        if self.sms_in:
            return device.receive_sms(self.phone, self.content)
        else:
            return device.send_sms(self.phone, self.content)


class GPSAppEnv(DynamicAppEnv):
    """
    This class describes the continuous updating GPS data inside device
    """

    def __init__(self, center_x=50, center_y=50, delta_x=1, delta_y=1, env_dict=None):
        if env_dict is not None:
            self.__dict__ = env_dict
            return
        self.center_x = center_x
        self.center_y = center_y
        self.delta_x = delta_x
        self.delta_y = delta_y
        self.env_type = 'gps'

    def deploy(self, device):
        return device.set_continuous_gps(self.center_x, self.center_y, self.delta_x, self.delta_y)


ENV_TYPES = {
    'contact': ContactAppEnv,
    'settings': SettingsAppEnv,
    'calllog': CallLogEnv,
    'smslog': SMSLogEnv,
    'gps': GPSAppEnv
}


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
        self.enabled = True

        if not self.policy:
            self.policy = POLICY_NONE

        if self.policy == POLICY_NONE:
            self.env_factory = None
        elif self.policy == POLICY_DUMMY:
            self.env_factory = DummyEnvFactory()
        elif self.policy == POLICY_STATIC:
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
        :return:
        """
        self.logger.info("Start deploying environment, policy is %s" % self.policy)
        if self.env_factory is not None:
            self.envs = self.generate_from_factory(self.env_factory)
        if self.envs is None:
            return
        for env in self.envs:
            if not self.enabled:
                break
            self.device.add_env(env)

        self.logger.debug("Finish deploying environment")
        if self.device.output_dir is not None:
            out_file = open(os.path.join(self.device.output_dir, "droidbot_env.json"), "w")
            self.dump(out_file)
            out_file.close()
            self.logger.debug("Environment settings saved to droidbot_env.json")

    def dump(self, env_file):
        """
        dump the environment information to a file
        :param env_file: the file to output the environment
        :return:
        """
        env_array = []
        for env in self.envs:
            env_array.append(env.to_dict())
        env_json = json.dumps(env_array)
        env_file.write(env_json)

    def generate_from_factory(self, app_env_factory):
        """
        generate the environment of app from factory
        :param app_env_factory: the AppEnvFactory instance used to generate
        :return:
        """
        return app_env_factory.produce_envs()

    def stop(self):
        self.enabled = False


class AppEnvFactory(object):
    """
    This class is responsible for produce a list of static and dynamic AppEnv
    """

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
        envs = [ContactAppEnv(), SettingsAppEnv(), CallLogEnv(), SMSLogEnv(), GPSAppEnv(), DummyFilesEnv()]
        return envs


class StaticEnvFactory(AppEnvFactory):
    """
    A factory which generate ad hoc environment based on static analysis result of app
    """

    def __init__(self, app):
        """
        create a StaticEnvFactory from app analysis result
        """
        self.app = app

    def produce_envs(self):
        """
        generate app-specific envs
        """
        envs = []
        permissions = self.app.permissions
        if 'android.permission.READ_CONTACTS' in permissions:
            envs.append(ContactAppEnv())
        if 'android.permission.READ_CALL_LOG' in permissions:
            envs.append(CallLogEnv())
            envs.append(CallLogEnv(call_in=False))
            envs.append(CallLogEnv(accepted=False))
        if 'android.permission.ACCESS_FINE_LOCATION' in permissions:
            envs.append(GPSAppEnv())
        if 'android.permission.READ_SMS' in permissions:
            envs.append(SMSLogEnv())
            envs.append(SMSLogEnv(sms_in=False))
        if 'android.permission.READ_EXTERNAL_STORAGE' in permissions \
                or 'android.permission.WRITE_EXTERNAL_STORAGE' in permissions \
                or 'android.permission.MOUNT_UNMOUNT_FILESYSTEMS' in permissions:
            envs.append(DummyFilesEnv())

        # TODO add more app-specific app environment
        return envs


class FileEnvFactory(AppEnvFactory):
    """
    A factory which generate environment from file
    """

    def __init__(self, env_file):
        """
        create a FileEnvFactory from a json file
        :param env_file path string
        """
        self.envs = []
        self.file = env_file
        f = open(env_file, 'r')
        env_array = json.load(f)
        for env_dict in env_array:
            if not isinstance(env_dict, dict):
                raise UnknownEnvException
            if 'env_type' not in env_dict:
                raise UnknownEnvException
            env_type = env_dict['env_type']
            if 'env_type' not in ENV_TYPES:
                raise UnknownEnvException
            EnvType = ENV_TYPES[env_type]
            env = EnvType(dict=env_dict)
            self.envs.append(env)
        self.index = 0

    def produce_envs(self):
        """
        generate envs from file
        """
        env = self.envs[self.index]
        self.index += 1
        return env
