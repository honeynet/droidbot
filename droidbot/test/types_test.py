# test script of types.py
__author__ = 'yuanchun'
from unittest import TestCase
from droidbot.types import Device, App, Intent


class DeviceTest(TestCase):
    """
    test the Device class,
    before testing, please make sure a emulator is started
    """
    def setUp(self):
        self.device = Device()

    def test_init(self):
        device_emulator = Device()
        self.assertTrue(device_emulator.is_connected)
        self.assertIsNotNone(device_emulator.get_display_info())

        device_real = Device(is_emulator=False)
        self.assertTrue(device_real.is_connected)

    def test_connect(self):
        if self.device.is_emulator:
            self.assertIsNotNone(self.device.get_adb())
            self.assertIsNotNone(self.device.get_telnet())
            self.assertIsNotNone(self.device.get_view_client())
        else:
            self.assertIsNotNone(self.device.get_adb())
            self.assertIsNotNone(self.device.get_telnet())
        self.device.check_connectivity()
        self.device.disconnect()
        self.device.connect()

