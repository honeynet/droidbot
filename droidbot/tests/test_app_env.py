# Test script of app_env.py
__author__ = 'yuanchun'
import json
import unittest

from droidbot.app_env import CallLogEnv, ContactAppEnv, \
    GPSAppEnv, SettingsAppEnv, SMSLogEnv
from types.device import Device


class TestEnv(unittest.TestCase):
    def setUp(self):
        self.call_log_env = CallLogEnv()
        self.contact_env = ContactAppEnv()
        self.gps_env = GPSAppEnv()
        self.settings_env = SettingsAppEnv()
        self.sms_log_env = SMSLogEnv()

    def test_to_json(self):
        app_env_json = self.call_log_env.to_json()
        app_env_json_dict = json.loads(app_env_json)
        self.assertTrue('env_type' in app_env_json_dict.keys())

    def test_deploy(self):
        device = Device("emulator-5554")
        self.assertTrue(self.call_log_env.deploy(device))
        self.assertTrue(self.contact_env.deploy(device))
        self.assertTrue(self.gps_env.deploy(device))
        self.assertTrue(self.settings_env.deploy(device))
        self.assertTrue(self.sms_log_env.deploy(device))
        device.disconnect()


class TestEnvFactory(unittest.TestCase):
    pass


class TestEnvManager(unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()