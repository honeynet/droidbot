__author__ = 'yuanchun'
import json
from unittest import TestCase
from droidbot.types import Intent
from droidbot.app_event import AppEvent, ContextEvent, DragEvent,\
    EmulatorEvent, KeyEvent, LongTouchEvent, IntentEvent, TouchEvent,\
    UIEvent, AppEventManager


class TestEvent(TestCase):
    def setUp(self):
        self.touch_event = TouchEvent(50, 50)
        intent = Intent(prefix="start", suffix="com.android.settings")
        self.intent_event = IntentEvent(intent=intent)
        self.long_touch_event = LongTouchEvent(50, 50)
        self.key_event = KeyEvent("HOME")
        self.emulator_event = EmulatorEvent(
            event_name="call", event_data={"phone":"1234567"})
        self.drag_event = DragEvent(50, 50, 100, 100)
        self.context_event = ContextEvent(context=None, event=self.touch_event)

    def test_to_json(self):
        touch_event_json = self.touch_event.to_json()
        touch_event_dict = json.loads(touch_event_json)
        self.assertTrue("event_type" in touch_event_dict.keys())


class TestEventManager(TestCase):
    pass


class TestEventFactory(TestEvent):
    pass