__author__ = 'yuanchun'
import time
from unittest import TestCase
from droidbot.connection import ADB, TelnetConsole, MonkeyRunner
from droidbot.types import Device


class TestADB(TestCase):
    def setUp(self):
        self.adb = ADB(Device())

    def test_connect(self):
        self.assertTrue(self.adb.check_connectivity())
        self.adb.disconnect()

    def test_run_cmd(self):
        r = self.adb.run_cmd(['get-state'])
        self.assertTrue(r.startswith('device'))
        r = self.adb.run_cmd("get-state")
        self.assertTrue(r.startswith('device'))


class TestTelnet(TestCase):
    def setUp(self):
        self.telnet = TelnetConsole(Device())

    def test_connect(self):
        self.assertTrue(self.telnet.check_connectivity())
        self.telnet.disconnect()

    def test_run_cmd(self):
        self.assertTrue(self.telnet.run_cmd("help"))
        self.assertTrue(self.telnet.run_cmd(['help']))
        self.assertFalse(self.telnet.run_cmd("unknown"))


class TestMonkeyRunner(TestCase):
    def setUp(self):
        self.monkeyrunner = MonkeyRunner(Device())

    def test_connect(self):
        self.assertTrue(self.monkeyrunner.check_connectivity())
        self.monkeyrunner.disconnect()
