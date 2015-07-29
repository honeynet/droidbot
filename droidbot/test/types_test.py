# test script of types.py
__author__ = 'yuanchun'
import time
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
        self.assertTrue(self.device.is_connected)

    def test_is_foreground(self):
        settings_app = App(package_name="com.android.settings")
        no_app = App()
        self.device.get_adb().press('HOME')
        time.sleep(2)
        self.assertTrue(self.device.is_foreground(no_app))
        self.assertFalse(self.device.is_foreground(settings_app))

        self.device.start_app(settings_app)
        time.sleep(2)
        self.assertTrue(settings_app)
        self.assertFalse("com.android.unknown")

    def test_add_contact(self):
        contact_data = {
            'name': 'Lynn',
            'phone': '1234567890'
        }
        r = self.device.add_contact(contact_data)
        self.assertTrue(r)

    def test_call(self):
        phone_num = "1234567890"

        r = self.device.call(phone_num)
        self.assertTrue(r)

        r = self.device.cancel_call(phone_num)
        self.assertTrue(r)

        r = self.device.receive_call(phone_num)
        self.assertTrue(r)

        r = self.device.accept_call(phone_num)
        self.assertTrue(r)

        r = self.device.cancel_call(phone_num)
        self.assertTrue(r)

    def test_sms(self):
        r = self.device.send_sms()
        self.assertTrue(r)

        r = self.device.receive_sms()
        self.assertTrue(r)

    def test_set_gps(self):
        r = self.device.set_gps(10, 10)
        self.assertTrue(r)

    def test_settings(self):
        self.device.change_settings(table_name='system', name='volume_system', value='10')
        self.assertEqual(self.device.get_settings()['system']['volume_system'], '10')
        self.device.change_settings(table_name='system', name='volume_system', value='20')
        self.assertEqual(self.device.get_settings()['system']['volume_system'], '20')


class AppTest(TestCase):
    """
    test the App class
    """
    def setUp(self):
        self.app = App(app_path="resources/TestDroidbot.apk")

    def test_init(self):
        noapp = App()
        self.assertTrue(noapp.whole_device)

        app_with_package_name = App(package_name="com.android.settings")
        self.assertFalse(app_with_package_name.whole_device)
        # TODO test get app path function
        # self.assertIsNotNone(app_with_package_name.get_app_path())

        app_with_file_path = self.app
        self.assertFalse(app_with_file_path.whole_device)
        self.assertEqual(app_with_file_path.get_package_name(), 'com.android.browser')

    def test_get_package_name(self):
        package_name = self.app.get_package_name()
        self.assertEqual(package_name, "com.lynnlyc")

    def test_get_main_activity(self):
        main_activity = self.app.get_main_activity()
        self.assertEqual(main_activity, "MainActivity")

    def test_get_possible_broadcasts(self):
        possible_broadcasts = self.app.get_possible_broadcasts()
        self.assertIsNotNone(possible_broadcasts)
        # TODO modify testDroidbot app, and fix this assertion
        i = Intent(prefix='broadcast', action="", category="")
        self.assertIn(i, possible_broadcasts)