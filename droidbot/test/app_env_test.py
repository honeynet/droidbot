# Test script of app_env.py
__author__ = 'yuanchun'
import time
import json
from unittest import TestCase
from droidbot.types import Device
from droidbot.app_env import AppEnv, CallLogEnv, ContactAppEnv, \
    GPSAppEnv, SettingsAppEnv, SMSLogEnv


class TestEvents(TestCase):
    def setUp(self):
        self.app_env = AppEnv()
        self.calllog_env = CallLogEnv()
        self.contact_env = ContactAppEnv()
        self.gps_env = GPSAppEnv()
        self.settings_env = SettingsAppEnv()
        self.smslog_env = SMSLogEnv()

    def test_to_json(self):
        app_env_json = self.app_env.to_json()
        app_env_json_dict = json.loads(app_env_json)
        self.assertTrue(app_env_json_dict.has_key('env_type'))

    def test_deploy(self):
        device = Device()
        self.app_env.deploy(device)
        self.calllog_env.deploy(device)
        self.contact_env.deploy(device)
        self.gps_env.deploy(device)
        self.settings_env.deploy(device)
        self.smslog_env.deploy(device)
        # TODO use TestDroidbot.apk to check the envs are deployed


class TestEnvFactory(TestCase):
    pass


class TestEnvManager(TestCase):
    pass