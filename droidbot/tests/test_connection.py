__author__ = 'yuanchun'
import unittest

from adapter.adb import ADB, TelnetConsole
from types.device import Device


class TestADB(unittest.TestCase):
    def setUp(self):
        self.device=Device("emulator-5554")
        self.adb = ADB(self.device)

    def test_connect(self):
        self.assertTrue(self.adb.check_connectivity())

    def test_run_cmd(self):
        r = self.adb.run_cmd(['get-state'])
        self.assertTrue(r.startswith('device'))
        r = self.adb.run_cmd("get-state")
        self.assertTrue(r.startswith('device'))

    def tearDown(self):
        self.adb.disconnect()
        self.device.disconnect()


class TestTelnet(unittest.TestCase):
    def setUp(self):
        self.device=Device("emulator-5554")
        self.telnet = TelnetConsole(self.device)

    def test_connect(self):
        self.assertTrue(self.telnet.check_connectivity())
        self.telnet.disconnect()

    def test_run_cmd(self):
        self.assertTrue(self.telnet.run_cmd("help"))
        self.assertTrue(self.telnet.run_cmd(['help']))
        self.assertFalse(self.telnet.run_cmd("unknown"))

    def tearDown(self):
        self.telnet.disconnect()
        self.device.disconnect()


# monkeyrunner connection is never used in droidbot
#
# class TestMonkeyRunner(TestCase):
#     def setUp(self):
#         self.device=Device("emulator-5554")
#         self.monkeyrunner = MonkeyRunner(self.device)
#
#     def test_connect(self):
#         self.assertTrue(self.monkeyrunner.check_connectivity())
#         self.monkeyrunner.disconnect()
#
#     def tearDown(self):
#         self.monkeyrunner.disconnect()
#         self.device.disconnect()


if __name__ == '__main__':
    unittest.main()