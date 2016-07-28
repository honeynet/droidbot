__author__ = 'yuanchun'
import json
import time
import unittest

from droidbot.app_event import ContextEvent, DragEvent,\
    EmulatorEvent, KeyEvent, LongTouchEvent, IntentEvent, TouchEvent, \
    ActivityNameContext, WindowNameContext
from types.device import Intent, Device


class TestEvent(unittest.TestCase):
    def setUp(self):
        self.touch_event = TouchEvent(50, 50)
        intent = Intent(prefix="start", suffix="com.android.settings")
        self.intent_event = IntentEvent(intent=intent)
        self.long_touch_event = LongTouchEvent(50, 50)
        self.key_event = KeyEvent("HOME")
        self.emulator_event = EmulatorEvent(
            event_name="call", event_data={"phone":"1234567"})
        self.drag_event = DragEvent(50, 50, 100, 100)

        self.activity_context = ActivityNameContext("dummy")
        self.window_context = ActivityNameContext("dummy")
        self.context_event1 = ContextEvent(context=self.activity_context, event=self.touch_event)
        self.context_event2 = ContextEvent(context=self.window_context, event=self.touch_event)

    def test_to_json(self):
        touch_event_json = self.touch_event.to_json()
        touch_event_dict = json.loads(touch_event_json)
        self.assertTrue("event_type" in touch_event_dict.keys())

    def test_send(self):
        device = Device("emulator-5554")
        self.assertTrue(self.touch_event.send(device))
        self.assertTrue(self.intent_event.send(device))
        self.assertTrue(self.long_touch_event.send(device))
        self.assertTrue(self.key_event.send(device))
        self.assertTrue(self.emulator_event.send(device))
        self.assertTrue(self.drag_event.send(device))
        self.assertTrue(self.context_event1.send(device))
        device.disconnect()

    def test_context(self):
        device = Device("emulator-5554")
        self.assertFalse(self.activity_context.assert_in_device(device))
        self.assertFalse(self.window_context.assert_in_device(device))

        settings_activity_context = ActivityNameContext("com.android.settings/.Settings")
        settings_window_context = WindowNameContext("com.android.settings/com.android.settings.Settings")
        device.start_app("com.android.settings")
        time.sleep(2)
        self.assertTrue(settings_activity_context.assert_in_device(device))
        self.assertTrue(settings_window_context.assert_in_device(device))

        device.disconnect()


class TestEventManager(unittest.TestCase):
    pass


class TestEventFactory(unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()